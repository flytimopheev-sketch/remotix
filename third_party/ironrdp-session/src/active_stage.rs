use std::borrow::Cow;
use std::sync::Arc;

use ironrdp_bulk::BulkCompressor;
use ironrdp_core::{ReadCursor, WriteBuf, decode, decode_cursor, encode_vec};
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::{DrdynvcClient, DvcProcessor, DynamicVirtualChannel};
use ironrdp_graphics::pointer::DecodedPointer;
use ironrdp_pdu::fast_path::{EncryptionFlags, FastPathHeader};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent, FastPathInputHeader};
use ironrdp_pdu::rdp::autodetect::AutoDetectRequest;
use ironrdp_pdu::rdp::client_info::CompressionType as PduCompressionType;
use ironrdp_pdu::rdp::headers::{BASIC_SECURITY_HEADER_SIZE, ShareDataPdu};
use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_pdu::rdpsec::{
    SEC_AUTODETECT_RSP, SEC_ENCRYPT, SEC_SECURE_CHECKSUM, SEC_TRANSPORT_RSP, SharedSecurity,
};
use ironrdp_pdu::slow_path::{self, GraphicsUpdateType};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, mcs};
use ironrdp_svc::{StaticChannelSet, SvcMessage, SvcProcessor, SvcProcessorMessages};
use tracing::{debug, info, warn};

use crate::fast_path::UpdateKind;
use crate::image::DecodedImage;
use crate::{SessionError, SessionErrorExt as _, SessionResult, fast_path, reason_err, x224};

/// Converts the PDU-layer compression type to the bulk crate's compression type.
fn to_bulk_compression_type(ct: PduCompressionType) -> ironrdp_bulk::CompressionType {
    match ct {
        PduCompressionType::K8 => ironrdp_bulk::CompressionType::Rdp4,
        PduCompressionType::K64 => ironrdp_bulk::CompressionType::Rdp5,
        PduCompressionType::Rdp6 => ironrdp_bulk::CompressionType::Rdp6,
        PduCompressionType::Rdp61 => ironrdp_bulk::CompressionType::Rdp61,
    }
}

pub struct ActiveStage {
    x224_processor: x224::Processor,
    fast_path_processor: fast_path::Processor,
    enable_server_pointer: bool,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
    /// Standard RDP Security cryptor shared with the connector; `None` when
    /// the session was negotiated over TLS/CredSSP (or plaintext).
    security: Option<SharedSecurity>,
}

/// Builder for [`ActiveStage`].
///
/// All fields are required; they are typically taken straight from `ironrdp-connector`’s
/// `ConnectionResult` once the connection sequence is finalized.
pub struct ActiveStageBuilder {
    pub static_channels: StaticChannelSet,
    pub user_channel_id: u16,
    pub io_channel_id: u16,
    pub message_channel_id: Option<u16>,
    pub share_id: u32,
    /// The bulk compression type that was negotiated, if any.
    pub compression_type: Option<PduCompressionType>,
    /// Enable server-side pointer updates (client-side pointer rendering).
    pub enable_server_pointer: bool,
    /// Use software rendering mode for pointer bitmap generation.
    pub pointer_software_rendering: bool,
    /// Standard RDP Security cryptor handed over by the connector
    /// (`ConnectionResult::security`); `None` when not negotiated.
    pub security: Option<SharedSecurity>,
}

impl ActiveStageBuilder {
    pub fn build(self) -> ActiveStage {
        let Self {
            static_channels,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
            compression_type,
            enable_server_pointer,
            pointer_software_rendering,
            security,
        } = self;

        let x224_processor = x224::Processor::new(
            static_channels,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
        );

        // Create bulk decompressor if compression was negotiated
        let bulk_decompressor = compression_type.and_then(|ct| {
            let bulk_ct = to_bulk_compression_type(ct);
            match BulkCompressor::new(bulk_ct) {
                Ok(compressor) => {
                    info!(compression_type = %bulk_ct, "Bulk decompressor initialized for FastPath");
                    Some(compressor)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create bulk decompressor, compression disabled");
                    None
                }
            }
        });

        let fast_path_processor = fast_path::ProcessorBuilder {
            io_channel_id,
            user_channel_id,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            bulk_decompressor,
        }
        .build();

        ActiveStage {
            x224_processor,
            fast_path_processor,
            enable_server_pointer,
            io_channel_id,
            message_channel_id,
            security,
        }
    }
}

impl ActiveStage {
    pub fn update_mouse_pos(&mut self, x: u16, y: u16) {
        self.fast_path_processor.update_mouse_pos(x, y);
    }

    /// Encodes outgoing input events and modifies image if necessary (e.g for client-side pointer
    /// rendering).
    pub fn process_fastpath_input(
        &mut self,
        image: &mut DecodedImage,
        events: &[FastPathInputEvent],
    ) -> SessionResult<Vec<ActiveStageOutput>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // Mouse move events are prevalent, so we can preallocate space for
        // response frame + graphics update
        let mut output = Vec::with_capacity(2);

        // Encoding fastpath response frame
        // PERF: unnecessary copy
        let fastpath_input = FastPathInput::new(events.to_vec()).map_err(SessionError::decode)?;
        let frame = encode_vec(&fastpath_input).map_err(SessionError::encode)?;
        let frame = self.secure_outgoing_frame(frame)?;
        output.push(ActiveStageOutput::ResponseFrame(frame));

        // If pointer rendering is disabled - we can skip the rest
        if !self.enable_server_pointer {
            return Ok(output);
        }

        // If mouse was moved by client - we should update framebuffer to reflect new
        // pointer position
        let mouse_pos = events.iter().find_map(|event| match event {
            FastPathInputEvent::MouseEvent(event) => Some((event.x_position, event.y_position)),
            FastPathInputEvent::MouseEventEx(event) => Some((event.x_position, event.y_position)),
            _ => None,
        });

        let (mouse_x, mouse_y) = match mouse_pos {
            Some(mouse_pos) => mouse_pos,
            None => return Ok(output),
        };

        // Graphics update is only sent when update is visually changed the framebuffer
        if let Some(rect) = image.move_pointer(mouse_x, mouse_y)? {
            output.push(ActiveStageOutput::GraphicsUpdate(rect));
        }

        Ok(output)
    }

    /// Process a frame received from the server.
    pub fn process(
        &mut self,
        image: &mut DecodedImage,
        action: Action,
        frame: &[u8],
    ) -> SessionResult<Vec<ActiveStageOutput>> {
        let (mut stage_outputs, processor_updates) = match action {
            Action::FastPath => {
                let frame = self.decrypt_fast_path_frame(frame)?;
                let mut output = WriteBuf::new();
                let processor_updates = self.fast_path_processor.process(image, &frame, &mut output)?;
                (
                    vec![ActiveStageOutput::ResponseFrame(output.into_inner())],
                    processor_updates,
                )
            }
            Action::X224 => {
                let frame = self.decrypt_x224_frame(frame)?;
                let x224_outputs = self.x224_processor.process(&frame)?;
                let mut stage_outputs = Vec::new();
                let mut processor_updates = Vec::new();

                for output in x224_outputs {
                    match output {
                        x224::ProcessorOutput::GraphicsUpdate(data) => {
                            let updates = process_slow_path_graphics(&mut self.fast_path_processor, image, &data)?;
                            processor_updates.extend(updates);
                        }
                        x224::ProcessorOutput::PointerUpdate(data) => {
                            let updates = process_slow_path_pointer(&mut self.fast_path_processor, image, &data)?;
                            processor_updates.extend(updates);
                        }
                        other => {
                            stage_outputs.push(ActiveStageOutput::try_from(other)?);
                        }
                    }
                }

                (stage_outputs, processor_updates)
            }
        };

        for update in processor_updates {
            match update {
                UpdateKind::None => {}
                UpdateKind::Region(region) => {
                    stage_outputs.push(ActiveStageOutput::GraphicsUpdate(region));
                }
                UpdateKind::PointerDefault => {
                    stage_outputs.push(ActiveStageOutput::PointerDefault);
                }
                UpdateKind::PointerHidden => {
                    stage_outputs.push(ActiveStageOutput::PointerHidden);
                }
                UpdateKind::PointerPosition { x, y } => {
                    stage_outputs.push(ActiveStageOutput::PointerPosition { x, y });
                }
                UpdateKind::PointerBitmap(pointer) => {
                    stage_outputs.push(ActiveStageOutput::PointerBitmap(pointer));
                }
            }
        }

        // Standard RDP Security: every frame leaving for the wire is enveloped.
        for stage_output in &mut stage_outputs {
            if let ActiveStageOutput::ResponseFrame(frame) = stage_output {
                *frame = self.secure_outgoing_frame(core::mem::take(frame))?;
            }
        }

        Ok(stage_outputs)
    }

    //== Standard RDP Security (MS-RDPBCGR 5.3) ==//
    //
    // The cryptor (`SharedSecurity`) is created by the connector during the
    // Secure Settings Exchange and handed over through `ConnectionResult`;
    // from that point every byte on the wire (both directions) travels inside
    // the `[flags u16][pad u16][MAC 8B][RC4 cipher]` envelope. `decrypt_checked`
    // resynchronises the RC4 keystream via a MAC-guided scan, mirroring the
    // server's per-PDU keystream consumption.

    /// Decrypts an inbound fast-path frame. Unlike the slow-path envelope,
    /// the server does not prepend a 12-byte security header: the MAC sits
    /// directly after the fast-path header's length field, ahead of the
    /// RC4-encrypted update data (`[fpHdr][len][MAC 8B][cipher]`). The frame
    /// is rebuilt around the recovered update data with the ENCRYPTED bit
    /// cleared. No-op when the cryptor is unarmed or the bit is not set.
    fn decrypt_fast_path_frame<'a>(&self, frame: &'a [u8]) -> SessionResult<Cow<'a, [u8]>> {
        let Some(security) = &self.security else {
            return Ok(Cow::Borrowed(frame));
        };

        let mut cursor = ReadCursor::new(frame);
        let header = decode_cursor::<FastPathHeader>(&mut cursor).map_err(SessionError::decode)?;
        if !header.flags.contains(EncryptionFlags::ENCRYPTED) {
            return Ok(Cow::Borrowed(frame));
        }

        let body_offset = frame.len().saturating_sub(header.data_length);
        let Some(body) = frame.get(body_offset..) else {
            return Err(reason_err!(
                "fast path",
                "encrypted fast-path frame has an inconsistent length"
            ));
        };
        if body.len() < 8 {
            return Err(reason_err!(
                "fast path",
                "encrypted fast-path PDU is too short for a MAC"
            ));
        }

        let plaintext = security.lock().unwrap().decrypt_checked(&body[8..], &body[0..8]);

        let header = FastPathHeader::new(header.flags & !EncryptionFlags::ENCRYPTED, plaintext.len());
        let mut rebuilt = encode_vec(&header).map_err(SessionError::encode)?;
        rebuilt.extend_from_slice(&plaintext);

        Ok(Cow::Owned(rebuilt))
    }

    /// Decrypts an inbound slow-path frame: an MCS Send Data Indication whose
    /// user data starts with the `SEC_ENCRYPT` envelope. The frame is
    /// re-encoded around the recovered payload so the X.224 demux sees the
    /// plaintext shape. Frames without the envelope pass through untouched
    /// (this includes the plaintext license PDU quirk, whose embedded
    /// BasicSecurityHeader is consumed downstream).
    fn decrypt_x224_frame<'a>(&self, frame: &'a [u8]) -> SessionResult<Cow<'a, [u8]>> {
        let Some(security) = &self.security else {
            return Ok(Cow::Borrowed(frame));
        };

        let pdu = match decode::<X224<mcs::McsMessage<'_>>>(frame) {
            Ok(pdu) => pdu,
            Err(_) => return Ok(Cow::Borrowed(frame)),
        };

        let mcs::McsMessage::SendDataIndication(data) = pdu.0 else {
            return Ok(Cow::Borrowed(frame));
        };

        if data.user_data.len() < 4 {
            return Ok(Cow::Borrowed(frame));
        }
        let flags = u16::from_le_bytes([data.user_data[0], data.user_data[1]]);
        if flags & SEC_ENCRYPT == 0 {
            return Ok(Cow::Borrowed(frame));
        }
        if data.user_data.len() < 12 {
            return Err(reason_err!("x224", "encrypted slow-path PDU is too short for a MAC"));
        }

        let plaintext = security
            .lock()
            .unwrap()
            .decrypt_checked(&data.user_data[12..], &data.user_data[4..12]);

        let secured = mcs::McsMessage::SendDataIndication(mcs::SendDataIndication {
            initiator_id: data.initiator_id,
            channel_id: data.channel_id,
            user_data: Cow::Owned(plaintext),
        });
        let rebuilt = encode_vec(&X224(secured)).map_err(SessionError::encode)?;

        Ok(Cow::Owned(rebuilt))
    }

    /// Decrypts an inbound raw frame for out-of-band consumption, e.g. when the
    /// caller drives a Deactivation-Reactivation Sequence directly and steps the
    /// activation sequence itself. Keeping this in one place matters for
    /// standard RDP security: every received frame must advance the receive
    /// cipher stream — including fast-path updates the caller may discard — or
    /// all later decryptions desync into garbage.
    pub fn decrypt_inbound_frame<'a>(&self, action: Action, frame: &'a [u8]) -> SessionResult<Cow<'a, [u8]>> {
        match action {
            Action::FastPath => self.decrypt_fast_path_frame(frame),
            Action::X224 => self.decrypt_x224_frame(frame),
        }
    }

    /// Secures an outgoing plaintext frame produced by this stage: slow-path
    /// frames (leading TPKT byte) get their MCS user data enveloped per the
    /// channel MAC rules, fast-path input frames get an 8-byte MAC inserted
    /// ahead of the RC4-encrypted events. No-op when the cryptor is unarmed.
    ///
    /// Public so callers that step a reactivation sequence themselves (and
    /// therefore bypass [`Self::process`]) can still envelope their output;
    /// sending those PDUs unencrypted makes the server drop the connection.
    pub fn secure_outgoing_frame(&self, frame: Vec<u8>) -> SessionResult<Vec<u8>> {
        let Some(security) = &self.security else {
            return Ok(frame);
        };

        // The processor emits an empty response buffer for frames that need no
        // reply; there is nothing to envelope and writing it is a no-op.
        if frame.is_empty() {
            return Ok(frame);
        }

        if frame.first() == Some(&0x03) {
            self.secure_slow_path_frame(security, frame)
        } else {
            self.secure_fast_path_frame(security, frame)
        }
    }

    /// Envelopes the MCS user data of an outgoing slow-path frame.
    ///
    /// The MAC variant follows the channel rules observed on the wire with
    /// Windows servers: I/O-channel uplinks always carry the plain MAC, the
    /// message channel always uses the SECURE_CHECKSUM counter MAC, and the
    /// remaining static channels switch to the counter MAC once that variant
    /// is armed (Demand Active extraFlags 0x10). Message-channel PDUs that
    /// embed their own 4-byte BasicSecurityHeader (autodetect responses)
    /// dissolve it into the envelope: the type bits travel in the envelope
    /// flags and the 4 bytes are struck from the body.
    fn secure_slow_path_frame(&self, security: &SharedSecurity, frame: Vec<u8>) -> SessionResult<Vec<u8>> {
        // A multi-chunk SVC payload (e.g. a Format Data Response split at the
        // negotiated channel chunk size) arrives here as a concatenation of
        // complete TPKT/X.224/MCS SendDataRequest PDUs. Each must be enveloped
        // on its own: dropping the trailing PDUs would leave the peer's
        // reassembly waiting forever, while enveloping the concatenation as a
        // single PDU would corrupt the crypto state.
        let mut secured = Vec::with_capacity(frame.len() + 64);
        let mut cursor = ReadCursor::new(&frame);
        while !cursor.remaining().is_empty() {
            let pdu = decode_cursor::<X224<mcs::McsMessage<'_>>>(&mut cursor).map_err(SessionError::decode)?;
            let mcs::McsMessage::SendDataRequest(req) = pdu.0 else {
                return Err(reason_err!(
                    "x224",
                    "outgoing frame is not an MCS Send Data Request (this is a bug)"
                ));
            };

            let mut flags = 0u16;
            let mut body = req.user_data.as_ref();
            let use_counter = if req.channel_id == self.io_channel_id {
                false
            } else if Some(req.channel_id) == self.message_channel_id {
                if body.len() >= BASIC_SECURITY_HEADER_SIZE {
                    let embedded = u16::from_le_bytes([body[0], body[1]]);
                    if embedded == SEC_AUTODETECT_RSP || embedded == SEC_TRANSPORT_RSP {
                        flags |= embedded;
                        body = &body[BASIC_SECURITY_HEADER_SIZE..];
                    }
                }
                true
            } else {
                security.lock().unwrap().secure_checksum
            };
            if use_counter {
                flags |= SEC_SECURE_CHECKSUM;
            }

            let envelope = security.lock().unwrap().encrypt_envelope(flags, body, use_counter);

            let single = mcs::SendDataRequest {
                initiator_id: req.initiator_id,
                channel_id: req.channel_id,
                user_data: Cow::Owned(envelope),
            };
            secured.extend_from_slice(&encode_vec(&X224(single)).map_err(SessionError::encode)?);
        }

        Ok(secured)
    }

    /// Envelopes the events of an outgoing fast-path input frame. Fast-path
    /// input travels on the I/O channel, so it always carries the plain MAC.
    ///
    /// Unlike the slow-path envelope ([flags u16][pad u16][MAC][cipher]), a
    /// fast-path input frame carries no security header: the 8-byte MAC sits
    /// directly after the fast-path header's length field ([MS-RDPBCGR 5.3.2]).
    /// `encrypt_envelope` emits the slow-path preamble, so build the envelope
    /// from the MAC and the RC4 keystream directly.
    fn secure_fast_path_frame(&self, security: &SharedSecurity, frame: Vec<u8>) -> SessionResult<Vec<u8>> {
        let mut cursor = ReadCursor::new(&frame);
        let header = decode_cursor::<FastPathInputHeader>(&mut cursor).map_err(SessionError::decode)?;
        let events_offset = frame.len().saturating_sub(header.data_length);

        let (mac, body) = {
            let mut security = security.lock().unwrap();
            let mac = security.mac(&frame[events_offset..], None);
            let body = security.encrypt(&frame[events_offset..]);
            (mac, body)
        };

        let secured_header = FastPathInputHeader {
            flags: EncryptionFlags::ENCRYPTED,
            data_length: mac.len() + body.len(),
            num_events: header.num_events,
        };
        let mut secured = encode_vec(&secured_header).map_err(SessionError::encode)?;
        secured.extend_from_slice(&mac);
        secured.extend_from_slice(&body);

        Ok(secured)
    }

    pub fn set_fastpath_processor(&mut self, processor: fast_path::Processor) {
        self.fast_path_processor = processor;
    }

    /// Updates the share_id used by the x224 processor for encoding ShareDataPdu.
    /// Must be called during Deactivation-Reactivation if the server assigns a new share_id.
    pub fn set_share_id(&mut self, share_id: u32) {
        self.x224_processor.set_share_id(share_id);
    }

    pub fn set_enable_server_pointer(&mut self, enable_server_pointer: bool) {
        self.enable_server_pointer = enable_server_pointer;
    }

    /// Encodes client-side graceful shutdown request. Note that upon sending this request,
    /// client should wait for server's ShutdownDenied PDU before closing the connection.
    ///
    /// Client-side graceful shutdown is defined in [MS-RDPBCGR]
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/27915739-8f77-487e-9927-55008af7fd68
    pub fn graceful_shutdown(&self) -> SessionResult<Vec<ActiveStageOutput>> {
        let mut frame = WriteBuf::new();
        self.x224_processor
            .encode_static(&mut frame, ShareDataPdu::ShutdownRequest)?;

        let frame = self.secure_outgoing_frame(frame.into_inner())?;

        Ok(vec![ActiveStageOutput::ResponseFrame(frame)])
    }

    /// Send a pdu on the static global channel. Typically used to send input events
    pub fn encode_static(&self, output: &mut WriteBuf, pdu: ShareDataPdu) -> SessionResult<usize> {
        let mut frame = WriteBuf::new();
        self.x224_processor.encode_static(&mut frame, pdu)?;

        let frame = self.secure_outgoing_frame(frame.into_inner())?;
        output.write_slice(&frame);
        Ok(frame.len())
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&mut self) -> Option<&T> {
        self.x224_processor.get_svc_processor()
    }

    pub fn get_svc_processor_mut<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.x224_processor.get_svc_processor_mut()
    }

    pub fn get_dvc<T: DvcProcessor + 'static>(&mut self) -> Option<&DynamicVirtualChannel> {
        self.x224_processor.get_dvc::<T>()
    }

    pub fn get_dvc_by_channel_id(&mut self, channel_id: u32) -> Option<&DynamicVirtualChannel> {
        self.x224_processor.get_dvc_by_channel_id(channel_id)
    }

    /// Completes user's SVC request with data, required to sent it over the network and returns
    /// a buffer with encoded data.
    pub fn process_svc_processor_messages<C: SvcProcessor + 'static>(
        &self,
        messages: SvcProcessorMessages<C>,
    ) -> SessionResult<Vec<u8>> {
        let frame = self.x224_processor.process_svc_processor_messages(messages)?;
        self.secure_outgoing_frame(frame)
    }

    /// Fully encodes a resize request for sending over the Display Control Virtual Channel.
    ///
    /// If the Display Control Virtual Channel is not available, or not yet connected, this method
    /// will return `None`.
    ///
    /// Per [2.2.2.2.1]:
    /// - The `width` MUST be greater than or equal to 200 pixels and less than or equal to 8192 pixels, and MUST NOT be an odd value.
    /// - The `height` MUST be greater than or equal to 200 pixels and less than or equal to 8192 pixels.
    /// - The `scale_factor` MUST be ignored if it is less than 100 percent or greater than 500 percent.
    /// - The `physical_dims` (width, height) MUST be ignored if either is less than 10 mm or greater than 10,000 mm.
    ///
    /// Use [`ironrdp_displaycontrol::pdu::MonitorLayoutEntry::adjust_display_size`] to adjust `width` and `height` before calling this function
    /// to ensure the display size is within the valid range.
    ///
    /// [2.2.2.2.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/ea2de591-9203-42cd-9908-be7a55237d1c
    pub fn encode_resize(
        &mut self,
        width: u32,
        height: u32,
        scale_factor: Option<u32>,
        physical_dims: Option<(u32, u32)>,
    ) -> Option<SessionResult<Vec<u8>>> {
        if let Some(dvc) = self.get_dvc::<DisplayControlClient>() {
            if let Some(channel_id) = dvc.channel_id() {
                let display_control = dvc.channel_processor_downcast_ref::<DisplayControlClient>()?;
                let svc_messages = match display_control.encode_single_primary_monitor(
                    channel_id,
                    width,
                    height,
                    scale_factor,
                    physical_dims,
                ) {
                    Ok(messages) => messages,
                    Err(e) => return Some(Err(SessionError::encode(e))),
                };

                return Some(
                    self.process_svc_processor_messages(SvcProcessorMessages::<DrdynvcClient>::new(svc_messages)),
                );
            } else {
                debug!("Could not encode a resize: Display Control Virtual Channel is not yet connected");
            }
        } else {
            debug!("Could not encode a resize: Display Control Virtual Channel is not available");
        }

        None
    }

    pub fn encode_dvc_messages(&mut self, messages: Vec<SvcMessage>) -> SessionResult<Vec<u8>> {
        self.process_svc_processor_messages(SvcProcessorMessages::<DrdynvcClient>::new(messages))
    }
}

#[derive(Debug)]
pub enum ActiveStageOutput {
    ResponseFrame(Vec<u8>),
    GraphicsUpdate(InclusiveRectangle),
    PointerDefault,
    PointerHidden,
    PointerPosition {
        x: u16,
        y: u16,
    },
    PointerBitmap(Arc<DecodedPointer>),
    Terminate(GracefulDisconnectReason),
    /// Received a Server Deactivate All PDU. The consumer should execute the [Deactivation-Reactivation Sequence].
    ///
    /// [Deactivation-Reactivation Sequence]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
    DeactivateAll,
    /// Server Initiate Multitransport Request. The application should establish a
    /// sideband UDP transport using the provided request parameters.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.15.1].
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
    MultitransportRequest(MultitransportRequestPdu),
    /// Server-reported network characteristics ([\[MS-RDPBCGR\] 2.2.14.1.5]).
    ///
    /// Contains an [`AutoDetectRequest::NetworkCharacteristicsResult`] with
    /// RTT and/or bandwidth measurements computed by the server.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.14.1.5].
    ///
    /// [\[MS-RDPBCGR\] 2.2.14.1.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/228ffc5c-b60c-4d3e-9781-ac613f822fdf
    AutoDetect(AutoDetectRequest),
}

impl TryFrom<x224::ProcessorOutput> for ActiveStageOutput {
    type Error = SessionError;

    fn try_from(value: x224::ProcessorOutput) -> Result<Self, Self::Error> {
        match value {
            x224::ProcessorOutput::ResponseFrame(frame) => Ok(Self::ResponseFrame(frame)),
            x224::ProcessorOutput::Disconnect(desc) => {
                let desc = match desc {
                    x224::DisconnectDescription::McsDisconnect(reason) => match reason {
                        mcs::DisconnectReason::ProviderInitiated => GracefulDisconnectReason::ServerInitiated,
                        mcs::DisconnectReason::UserRequested => GracefulDisconnectReason::UserInitiated,
                        other => GracefulDisconnectReason::Other(other.description().to_owned()),
                    },
                    x224::DisconnectDescription::ErrorInfo(info) => GracefulDisconnectReason::Other(info.description()),
                };

                Ok(Self::Terminate(desc))
            }
            x224::ProcessorOutput::DeactivateAll => Ok(Self::DeactivateAll),
            x224::ProcessorOutput::MultitransportRequest(pdu) => Ok(Self::MultitransportRequest(pdu)),
            x224::ProcessorOutput::AutoDetect(request) => Ok(Self::AutoDetect(request)),
            // GraphicsUpdate and PointerUpdate are consumed in ActiveStage::process()
            // before reaching this conversion.
            x224::ProcessorOutput::GraphicsUpdate(_) | x224::ProcessorOutput::PointerUpdate(_) => Err(
                SessionError::general("slow-path graphics/pointer updates should be handled before this conversion"),
            ),
        }
    }
}

/// Reasons for graceful disconnect. This type provides GUI-friendly descriptions for
/// disconnect reasons.
#[derive(Debug, Clone)]
pub enum GracefulDisconnectReason {
    UserInitiated,
    ServerInitiated,
    Other(String),
}

impl GracefulDisconnectReason {
    pub fn description(&self) -> String {
        match self {
            GracefulDisconnectReason::UserInitiated => "user initiated disconnect".to_owned(),
            GracefulDisconnectReason::ServerInitiated => "server initiated disconnect".to_owned(),
            GracefulDisconnectReason::Other(description) => description.clone(),
        }
    }
}

impl core::fmt::Display for GracefulDisconnectReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.description())
    }
}

/// Parse and process a slow-path graphics update through the shared bitmap pipeline.
fn process_slow_path_graphics(
    fast_path_processor: &mut fast_path::Processor,
    image: &mut DecodedImage,
    data: &[u8],
) -> SessionResult<Vec<UpdateKind>> {
    let mut src = ReadCursor::new(data);
    let update_type = slow_path::read_graphics_update_type(&mut src).map_err(SessionError::decode)?;

    match update_type {
        GraphicsUpdateType::Bitmap => {
            let bitmap = slow_path::decode_slow_path_bitmap(&mut src).map_err(SessionError::decode)?;
            fast_path_processor.process_bitmap_update(image, bitmap)
        }
        GraphicsUpdateType::Orders => {
            warn!("Slow-path drawing orders not supported (MS-RDPEGDI)");
            Ok(Vec::new())
        }
        GraphicsUpdateType::Palette => {
            warn!("Slow-path palette update not supported (8bpp)");
            Ok(Vec::new())
        }
        // Synchronize is an artifact from the T.128 multipoint protocol
        // and carries no data. Safe to ignore.
        GraphicsUpdateType::Synchronize => {
            debug!("Ignoring slow-path synchronize update");
            Ok(Vec::new())
        }
    }
}

/// Parse and process a slow-path pointer update through the shared pointer pipeline.
fn process_slow_path_pointer(
    fast_path_processor: &mut fast_path::Processor,
    image: &mut DecodedImage,
    data: &[u8],
) -> SessionResult<Vec<UpdateKind>> {
    let mut src = ReadCursor::new(data);
    let pointer = slow_path::decode_slow_path_pointer(&mut src).map_err(SessionError::decode)?;
    fast_path_processor.process_pointer_update(image, pointer)
}
