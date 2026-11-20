//! CLIPRDR — статический канал буфера обмена RDP (MS-RDPECLIP).
//!
//! Реализован только текстовый обмен: `CF_UNICODETEXT` (13) и, как
//! совместимый запасной вариант, `CF_TEXT` (1). Этого достаточно для
//! копирования/вставки текста между Remotix и удалённым рабочим столом.
//!
//! Файлы, изображения и HTML пока не объявляются: сервер не должен
//! предлагать пользователю форматы, которые клиент не умеет отдавать.
//! Содержимое буфера никогда не попадает в журнал — только направление,
//! формат и размер.

use std::collections::VecDeque;

use ironrdp_pdu::gcc::ChannelName;
use ironrdp_pdu::{pdu_other_err, PduResult};
use ironrdp_svc::{CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor};

use super::ClipboardConfig;

/// Имя статического канала в GCC-заголовке (8 байт с завершающим NUL).
const CHANNEL_NAME: ChannelName = ChannelName::from_static(b"cliprdr\0");

/// Заголовок CLIPRDR: MessageType (2) + MessageFlags (2) + DataLength (4).
const HEADER_SIZE: usize = 8;

const MSG_MONITOR_READY: u16 = 0x0001;
const MSG_FORMAT_LIST: u16 = 0x0002;
const MSG_FORMAT_LIST_RESPONSE: u16 = 0x0003;
const MSG_FORMAT_DATA_REQUEST: u16 = 0x0004;
const MSG_FORMAT_DATA_RESPONSE: u16 = 0x0005;
const MSG_TEMP_DIRECTORY: u16 = 0x0006;
const MSG_CLIP_CAPS: u16 = 0x0007;

const FLAG_RESPONSE_OK: u16 = 0x0001;
const FLAG_RESPONSE_FAIL: u16 = 0x0002;
const FLAG_ASCII_NAMES: u16 = 0x0004;

const CAPSTYPE_GENERAL: u16 = 0x0001;
const CAPS_VERSION_2: u32 = 2;
const GENERAL_FLAG_LONG_FORMAT_NAMES: u32 = 0x0002;

/// Короткое имя формата — фиксированный блок на 32 байта.
const SHORT_FORMAT_NAME_SIZE: usize = 32;

const CF_TEXT: u32 = 1;
const CF_UNICODETEXT: u32 = 13;

/// Ограничение на текст из удалённого буфера: защищает от случайного
/// или злонамеренного многомегабайтного ответа.
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEXT_UNITS: usize = MAX_TEXT_BYTES / 2;

/// Сколько запросов данных может ждать ответа. Буфер обмена может меняться
/// несколько раз подряд; ответы приходят по порядку, поэтому храним очередь,
/// а не один формат.
const MAX_PENDING_REQUESTS: usize = 8;

/// Событие, которое канал отдаёт GUI-слою.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// В удалённом буфере появился текст.
    Text(String),
}

/// Клиент канала CLIPRDR.
#[derive(Debug)]
pub struct CliprdrClient {
    config: ClipboardConfig,
    /// Актуальный локальный текст. `None` — буфер пуст или слишком велик.
    local_text: Option<String>,
    /// Сервер прислал Monitor Ready: можно объявлять форматы.
    remote_ready: bool,
    /// Сервер прислал Clipboard Capabilities: по MS-RDPECLIP только в этом
    /// случае клиент отвечает своими capabilities.
    server_caps_received: bool,
    /// Сервер поддерживает длинные имена форматов (generalFlags 0x2).
    server_long_names: bool,
    /// Форматы, которые мы запросили у сервера и ждём в Data Response.
    pending_requests: VecDeque<u32>,
    /// Текст, полученный от сервера, ещё не забранный GUI-потоком.
    events: VecDeque<ClipboardEvent>,
}

ironrdp_core::impl_as_any!(CliprdrClient);

impl CliprdrClient {
    pub fn new(config: ClipboardConfig) -> Self {
        Self {
            config,
            local_text: None,
            remote_ready: false,
            server_caps_received: false,
            server_long_names: false,
            pending_requests: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Обновляет локальный текст и, если канал готов, объявляет форматы
    /// удалённой стороне. Возвращает готовые к отправке SVC-сообщения.
    pub fn set_local_text(&mut self, text: Option<String>) -> Vec<SvcMessage> {
        let text = text.filter(|value| !value.is_empty());
        let too_large = text
            .as_deref()
            .map(|value| value.encode_utf16().count() > MAX_TEXT_UNITS)
            .unwrap_or(false);
        let text = if too_large {
            crate::logging::rdp_warn(
                "CLIPRDR: локальный текст слишком велик для отправки, буфер не объявлен",
            );
            None
        } else {
            text
        };

        if self.local_text == text {
            return Vec::new();
        }
        self.local_text = text;

        if !self.config.to_remote || !self.remote_ready {
            return Vec::new();
        }

        // Пустой список форматов сообщает серверу, что текста больше нет.
        vec![SvcMessage::from(self.format_list_pdu())]
    }

    /// Забирает накопленные события для GUI-потока.
    pub fn drain_events(&mut self) -> Vec<ClipboardEvent> {
        self.events.drain(..).collect()
    }

    /// Обе стороны используют длинные имена только тогда, когда сервер
    /// объявил их поддержку. Иначе по умолчанию действует короткий формат.
    fn use_long_names(&self) -> bool {
        self.server_long_names
    }

    fn client_caps_pdu(&self) -> Vec<u8> {
        let general_flags = if self.use_long_names() {
            GENERAL_FLAG_LONG_FORMAT_NAMES
        } else {
            0
        };

        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&1u16.to_le_bytes()); // cCapabilitiesSets
        data.extend_from_slice(&0u16.to_le_bytes()); // pad1
        data.extend_from_slice(&CAPSTYPE_GENERAL.to_le_bytes());
        // lengthCapability включает type (2) + length (2) + данные (8).
        data.extend_from_slice(&12u16.to_le_bytes());
        data.extend_from_slice(&CAPS_VERSION_2.to_le_bytes());
        data.extend_from_slice(&general_flags.to_le_bytes());
        build_pdu(MSG_CLIP_CAPS, 0, &data)
    }

    fn format_list_pdu(&self) -> Vec<u8> {
        let formats: &[u32] = if self.config.to_remote && self.local_text.is_some() {
            &[CF_UNICODETEXT, CF_TEXT]
        } else {
            &[]
        };
        build_pdu(
            MSG_FORMAT_LIST,
            0,
            &format_list_data(formats, self.use_long_names()),
        )
    }

    fn on_monitor_ready(&mut self) -> Vec<SvcMessage> {
        if self.remote_ready {
            return Vec::new();
        }
        self.remote_ready = true;
        crate::logging::rdp_info("CLIPRDR: канал готов");

        // MS-RDPECLIP: после Monitor Ready клиент отправляет capabilities,
        // если получил их от сервера, затем обязательно Format List — даже
        // пустой. Иначе буферы не синхронизируются.
        let mut out = Vec::with_capacity(2);
        if self.server_caps_received {
            out.push(SvcMessage::from(self.client_caps_pdu()));
        }
        out.push(SvcMessage::from(self.format_list_pdu()));
        out
    }

    fn on_clip_caps(&mut self, data: &[u8]) -> Vec<SvcMessage> {
        match parse_general_caps(data) {
            Some(flags) => {
                self.server_caps_received = true;
                self.server_long_names = flags & GENERAL_FLAG_LONG_FORMAT_NAMES != 0;
                crate::logging::rdp_info(&format!(
                    "CLIPRDR: capabilities сервера, generalFlags={flags:#010x}, длинные имена: {}",
                    if self.server_long_names {
                        "да"
                    } else {
                        "нет"
                    }
                ));
            }
            None => {
                crate::logging::rdp_warn("CLIPRDR: некорректные capabilities сервера");
            }
        }
        Vec::new()
    }

    fn on_temp_directory(&mut self, data: &[u8]) -> Vec<SvcMessage> {
        if data.len() == 520 {
            crate::logging::rdp_info("CLIPRDR: получен временный каталог (не используется)");
        } else {
            crate::logging::rdp_warn(&format!(
                "CLIPRDR: временный каталог неверной длины {}",
                data.len()
            ));
        }
        Vec::new()
    }

    fn on_format_list(&mut self, flags: u16, data: &[u8]) -> Vec<SvcMessage> {
        // CB_ASCII_NAMES означает короткие имена, даже если capability
        // длинных имён была согласована.
        let long_names = self.use_long_names() && flags & FLAG_ASCII_NAMES == 0;
        let formats = parse_format_list(data, long_names);
        crate::logging::rdp_info(&format!(
            "CLIPRDR: удалённый буфер предлагает {} формат(ов)",
            formats.len()
        ));

        let mut out = vec![SvcMessage::from(format_list_response(true))];
        if !self.config.from_remote {
            self.pending_requests.clear();
            return out;
        }

        let chosen = if formats.contains(&CF_UNICODETEXT) {
            Some(CF_UNICODETEXT)
        } else if formats.contains(&CF_TEXT) {
            Some(CF_TEXT)
        } else {
            None
        };

        match chosen {
            Some(format) => {
                if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                    crate::logging::rdp_warn(
                        "CLIPRDR: слишком много запросов данных, новый пропущен",
                    );
                } else {
                    self.pending_requests.push_back(format);
                    out.push(SvcMessage::from(format_data_request(format)));
                }
            }
            None => {
                // Удалённый буфер больше не содержит текста: ответы на
                // прошлые запросы уже неактуальны.
                self.pending_requests.clear();
                crate::logging::rdp_info("CLIPRDR: в удалённом буфере нет текста");
            }
        }
        out
    }

    fn on_format_data_request(&mut self, data: &[u8]) -> Vec<SvcMessage> {
        let Some(format) = read_u32(data) else {
            crate::logging::rdp_warn("CLIPRDR: некорректный Format Data Request");
            return vec![SvcMessage::from(format_data_response(false, &[]))];
        };

        if !self.config.to_remote {
            crate::logging::rdp_warn(
                "CLIPRDR: сервер запросил данные, но отправка в удалённый буфер отключена",
            );
            return vec![SvcMessage::from(format_data_response(false, &[]))];
        }

        let Some(text) = self.local_text.as_deref() else {
            crate::logging::rdp_warn("CLIPRDR: сервер запросил текст, но локальный буфер пуст");
            return vec![SvcMessage::from(format_data_response(false, &[]))];
        };

        let payload = match format {
            CF_UNICODETEXT => encode_utf16(text),
            CF_TEXT => encode_ansi(text),
            _ => {
                crate::logging::rdp_warn(&format!(
                    "CLIPRDR: запрошен неподдерживаемый формат {format}"
                ));
                return vec![SvcMessage::from(format_data_response(false, &[]))];
            }
        };

        if payload.len() > MAX_TEXT_BYTES {
            crate::logging::rdp_warn(&format!(
                "CLIPRDR: текст {} байт превышает лимит {MAX_TEXT_BYTES}",
                payload.len()
            ));
            return vec![SvcMessage::from(format_data_response(false, &[]))];
        }

        crate::logging::rdp_info(&format!(
            "CLIPRDR: локальный буфер -> удалённый, формат {format}, {} байт",
            payload.len()
        ));
        vec![SvcMessage::from(format_data_response(true, &payload))]
    }

    fn on_format_data_response(&mut self, flags: u16, data: &[u8]) -> Vec<SvcMessage> {
        let format = self.pending_requests.pop_front();
        if flags & FLAG_RESPONSE_OK == 0 {
            crate::logging::rdp_warn(&format!(
                "CLIPRDR: сервер не смог отдать данные (формат {:?})",
                format
            ));
            return Vec::new();
        }
        let Some(format) = format else {
            crate::logging::rdp_warn("CLIPRDR: данные пришли без запроса, пропущены");
            return Vec::new();
        };
        if data.len() > MAX_TEXT_BYTES {
            crate::logging::rdp_warn(&format!(
                "CLIPRDR: ответ {} байт превышает лимит {MAX_TEXT_BYTES}, пропущен",
                data.len()
            ));
            return Vec::new();
        }

        let text = match format {
            CF_UNICODETEXT => decode_utf16(data),
            CF_TEXT => decode_ansi(data),
            _ => {
                crate::logging::rdp_warn(&format!(
                    "CLIPRDR: ответ в неподдерживаемом формате {format}"
                ));
                return Vec::new();
            }
        };

        if text.is_empty() {
            return Vec::new();
        }

        crate::logging::rdp_info(&format!(
            "CLIPRDR: удалённый буфер -> локальный, формат {format}, {} байт",
            data.len()
        ));
        self.events.push_back(ClipboardEvent::Text(text));
        Vec::new()
    }

    fn handle(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let header = parse_header(payload)?;
        let messages = match header.message_type {
            MSG_MONITOR_READY => self.on_monitor_ready(),
            MSG_CLIP_CAPS => self.on_clip_caps(header.data),
            MSG_TEMP_DIRECTORY => self.on_temp_directory(header.data),
            MSG_FORMAT_LIST => self.on_format_list(header.flags, header.data),
            MSG_FORMAT_LIST_RESPONSE => {
                if header.flags & FLAG_RESPONSE_OK == 0 {
                    crate::logging::rdp_warn("CLIPRDR: сервер отклонил список форматов");
                }
                Vec::new()
            }
            MSG_FORMAT_DATA_REQUEST => self.on_format_data_request(header.data),
            MSG_FORMAT_DATA_RESPONSE => self.on_format_data_response(header.flags, header.data),
            other => {
                crate::logging::rdp_info(&format!(
                    "CLIPRDR: пропущено сообщение типа {other:#06x}"
                ));
                Vec::new()
            }
        };
        Ok(messages)
    }
}

impl SvcProcessor for CliprdrClient {
    fn channel_name(&self) -> ChannelName {
        CHANNEL_NAME
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        self.handle(payload)
    }
}

impl SvcClientProcessor for CliprdrClient {}

#[derive(Debug)]
struct Header<'a> {
    message_type: u16,
    flags: u16,
    data: &'a [u8],
}

fn parse_header(payload: &[u8]) -> PduResult<Header<'_>> {
    if payload.len() < HEADER_SIZE {
        return Err(pdu_other_err!("cliprdr", "CLIPRDR PDU короче заголовка"));
    }
    let message_type = u16::from_le_bytes([payload[0], payload[1]]);
    let flags = u16::from_le_bytes([payload[2], payload[3]]);
    let data_len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let mut end = HEADER_SIZE
        .checked_add(data_len)
        .ok_or_else(|| pdu_other_err!("cliprdr", "переполнение длины CLIPRDR PDU"))?;

    if payload.len() < end {
        // Некоторые серверы (например, gnome-remote-desktop) присылают
        // неуспешный ответ с неверной dataLen и без данных. Это не должно
        // рвать всю RDP-сессию: флаг ответа уже говорит, что данных нет.
        let failed_response = flags & FLAG_RESPONSE_FAIL != 0
            && matches!(
                message_type,
                MSG_FORMAT_LIST_RESPONSE | MSG_FORMAT_DATA_RESPONSE
            );
        if failed_response {
            crate::logging::rdp_warn(&format!(
                "CLIPRDR: ответ с ошибкой заявил {data_len} байт, получено {}; данные проигнорированы",
                payload.len().saturating_sub(HEADER_SIZE)
            ));
            end = payload.len();
        } else {
            return Err(pdu_other_err!(
                "cliprdr",
                "CLIPRDR PDU короче заявленной длины"
            ));
        }
    }
    let data = &payload[HEADER_SIZE..end];
    Ok(Header {
        message_type,
        flags,
        data,
    })
}

fn build_pdu(message_type: u16, flags: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + data.len());
    out.extend_from_slice(&message_type.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn format_list_response(ok: bool) -> Vec<u8> {
    let flags = if ok {
        FLAG_RESPONSE_OK
    } else {
        FLAG_RESPONSE_FAIL
    };
    build_pdu(MSG_FORMAT_LIST_RESPONSE, flags, &[])
}

fn format_data_request(format: u32) -> Vec<u8> {
    build_pdu(MSG_FORMAT_DATA_REQUEST, 0, &format.to_le_bytes())
}

fn format_data_response(ok: bool, data: &[u8]) -> Vec<u8> {
    let flags = if ok {
        FLAG_RESPONSE_OK
    } else {
        FLAG_RESPONSE_FAIL
    };
    build_pdu(MSG_FORMAT_DATA_RESPONSE, flags, data)
}

fn format_name(format: u32) -> &'static str {
    match format {
        CF_TEXT => "Text",
        CF_UNICODETEXT => "UnicodeText",
        _ => "",
    }
}

fn format_list_data(formats: &[u32], long_names: bool) -> Vec<u8> {
    let mut data = Vec::new();
    for &format in formats {
        data.extend_from_slice(&format.to_le_bytes());
        let name = format_name(format);
        if long_names {
            for unit in name.encode_utf16() {
                data.extend_from_slice(&unit.to_le_bytes());
            }
            data.extend_from_slice(&0u16.to_le_bytes());
        } else {
            // Short Format Name: 32-байтовый блок с Unicode-именем,
            // завершающимся NUL. Оставляем место под завершающий NUL.
            let mut block = [0u8; SHORT_FORMAT_NAME_SIZE];
            let max_units = SHORT_FORMAT_NAME_SIZE / 2 - 1;
            for (index, unit) in name.encode_utf16().take(max_units).enumerate() {
                let offset = index * 2;
                block[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            }
            data.extend_from_slice(&block);
        }
    }
    data
}

fn parse_format_list(data: &[u8], long_names: bool) -> Vec<u32> {
    let mut formats = Vec::new();
    let mut index = 0;
    while index + 4 <= data.len() {
        let format = u32::from_le_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]);

        if long_names {
            index += 4;
            formats.push(format);
            while index + 2 <= data.len() {
                let unit = u16::from_le_bytes([data[index], data[index + 1]]);
                index += 2;
                if unit == 0 {
                    break;
                }
            }
        } else {
            // Короткое имя — ровно 32 байта после formatId. Неполный
            // хвост не считается ещё одним форматом.
            let next = index + 4 + SHORT_FORMAT_NAME_SIZE;
            if next > data.len() {
                break;
            }
            formats.push(format);
            index = next;
        }
    }
    formats
}

/// Разбирает Clipboard Capabilities и возвращает generalFlags.
///
/// Если general capability set отсутствует, по MS-RDPECLIP действуют
/// значения по умолчанию, то есть generalFlags = 0.
fn parse_general_caps(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut index = 4usize;
    let mut general_flags = 0u32;

    for _ in 0..count {
        if index + 4 > data.len() {
            return None;
        }
        let set_type = u16::from_le_bytes([data[index], data[index + 1]]);
        let length = u16::from_le_bytes([data[index + 2], data[index + 3]]) as usize;
        if length < 4 || index + length > data.len() {
            return None;
        }
        if set_type == CAPSTYPE_GENERAL && length >= 12 {
            general_flags = u32::from_le_bytes([
                data[index + 8],
                data[index + 9],
                data[index + 10],
                data[index + 11],
            ]);
        }
        index += length;
    }

    Some(general_flags)
}

fn read_u32(data: &[u8]) -> Option<u32> {
    (data.len() >= 4).then(|| u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn encode_utf16(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Символы Windows-1252 для байтов 0x80..=0x9F.
///
/// Байты 0xA0..=0xFF совпадают с Latin-1, поэтому их можно преобразовать
/// напрямую. Для 0x80..=0x9F нужна таблица: иначе UTF-8-декодирование
/// превратило бы, например, `0xE9` в символ замены.
const WINDOWS_1252_SPECIAL: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

fn decode_windows_1252_byte(byte: u8) -> char {
    match byte {
        0x80..=0x9F => WINDOWS_1252_SPECIAL[(byte - 0x80) as usize],
        _ => char::from(byte),
    }
}

fn encode_windows_1252_char(ch: char) -> Option<u8> {
    if let Some(index) = WINDOWS_1252_SPECIAL.iter().position(|&item| item == ch) {
        return Some(0x80 + index as u8);
    }
    let code = ch as u32;
    if code <= 0xFF && !(0x80..=0x9F).contains(&code) {
        Some(code as u8)
    } else {
        None
    }
}

/// CF_TEXT в Windows — ANSI/Windows-1252. Для символов вне кодировки
/// используем `?`: лучше потерять редкий символ, чем отправить серверу
/// битую последовательность.
fn encode_ansi(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 1);
    for ch in text.chars() {
        out.push(encode_windows_1252_char(ch).unwrap_or(b'?'));
    }
    out.push(0);
    out
}

fn decode_utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_ansi(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    data[..end]
        .iter()
        .map(|byte| decode_windows_1252_byte(*byte))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(to_remote: bool, from_remote: bool) -> ClipboardConfig {
        ClipboardConfig {
            enabled: true,
            to_remote,
            from_remote,
        }
    }

    fn payloads(messages: Vec<SvcMessage>) -> Vec<Vec<u8>> {
        messages
            .into_iter()
            .map(|message| message.encode_unframed_pdu().expect("encode"))
            .collect()
    }

    fn process(client: &mut CliprdrClient, pdu: Vec<u8>) -> Vec<Vec<u8>> {
        let messages = client.process(&pdu).expect("CLIPRDR PDU");
        payloads(messages)
    }

    fn monitor_ready() -> Vec<u8> {
        build_pdu(MSG_MONITOR_READY, 0, &[])
    }

    fn server_caps(general_flags: u32) -> Vec<u8> {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&CAPSTYPE_GENERAL.to_le_bytes());
        data.extend_from_slice(&12u16.to_le_bytes());
        data.extend_from_slice(&CAPS_VERSION_2.to_le_bytes());
        data.extend_from_slice(&general_flags.to_le_bytes());
        build_pdu(MSG_CLIP_CAPS, 0, &data)
    }

    fn format_list(formats: &[u32], long_names: bool) -> Vec<u8> {
        build_pdu(MSG_FORMAT_LIST, 0, &format_list_data(formats, long_names))
    }

    #[test]
    fn header_is_eight_bytes() {
        assert_eq!(HEADER_SIZE, 8);
        assert_eq!(
            monitor_ready(),
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn client_caps_have_general_set() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, server_caps(0));
        let out = process(&mut client, monitor_ready());
        assert_eq!(out.len(), 2, "caps + обязательный Format List");
        assert_eq!(out[0].len(), 24);
        assert_eq!(&out[0][0..2], &MSG_CLIP_CAPS.to_le_bytes());
        assert_eq!(&out[0][2..4], &0u16.to_le_bytes());
        assert_eq!(&out[0][4..8], &16u32.to_le_bytes());
        assert_eq!(&out[0][8..10], &1u16.to_le_bytes());
        assert_eq!(&out[0][10..12], &0u16.to_le_bytes());
        assert_eq!(&out[0][12..14], &CAPSTYPE_GENERAL.to_le_bytes());
        assert_eq!(&out[0][14..16], &12u16.to_le_bytes());
        assert_eq!(&out[0][16..20], &CAPS_VERSION_2.to_le_bytes());
        assert_eq!(&out[0][20..24], &0u32.to_le_bytes());
        assert!(out[1][HEADER_SIZE..].is_empty());
    }

    #[test]
    fn monitor_ready_without_server_caps_sends_only_format_list() {
        let mut client = CliprdrClient::new(config(true, true));
        let out = process(&mut client, monitor_ready());
        assert_eq!(out.len(), 1, "без caps сервера клиент не шлёт свои");
        assert_eq!(&out[0][0..2], &MSG_FORMAT_LIST.to_le_bytes());
        assert!(out[0][HEADER_SIZE..].is_empty());
    }

    #[test]
    fn server_long_names_are_negotiated() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, server_caps(GENERAL_FLAG_LONG_FORMAT_NAMES));
        let _ = client.set_local_text(Some("hello".to_string()));
        let out = process(&mut client, monitor_ready());
        assert_eq!(out.len(), 2);
        assert_eq!(
            &out[0][20..24],
            &GENERAL_FLAG_LONG_FORMAT_NAMES.to_le_bytes()
        );
        assert_eq!(
            parse_format_list(&out[1][HEADER_SIZE..], true),
            vec![CF_UNICODETEXT, CF_TEXT]
        );
    }

    #[test]
    fn short_format_list_roundtrip_keeps_ids() {
        let data = format_list_data(&[CF_UNICODETEXT, CF_TEXT], false);
        assert_eq!(data.len(), 2 * (4 + SHORT_FORMAT_NAME_SIZE));
        assert_eq!(
            parse_format_list(&data, false),
            vec![CF_UNICODETEXT, CF_TEXT]
        );
    }

    #[test]
    fn long_format_list_roundtrip_keeps_ids() {
        let data = format_list_data(&[CF_UNICODETEXT, CF_TEXT], true);
        assert_eq!(
            parse_format_list(&data, true),
            vec![CF_UNICODETEXT, CF_TEXT]
        );
    }

    #[test]
    fn ascii_short_format_names_are_skipped() {
        let mut data = Vec::new();
        data.extend_from_slice(&CF_TEXT.to_le_bytes());
        let mut block = [0u8; SHORT_FORMAT_NAME_SIZE];
        block[..4].copy_from_slice(b"Text");
        data.extend_from_slice(&block);
        data.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
        let mut block = [0u8; SHORT_FORMAT_NAME_SIZE];
        block[..11].copy_from_slice(b"UnicodeText");
        data.extend_from_slice(&block);
        assert_eq!(
            parse_format_list(&data, false),
            vec![CF_TEXT, CF_UNICODETEXT]
        );
    }

    #[test]
    fn remote_text_is_requested_and_decoded() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, monitor_ready());

        let out = process(&mut client, format_list(&[CF_UNICODETEXT], false));
        assert_eq!(out.len(), 2, "ожидались ответ списка и запрос данных");
        assert_eq!(out[0], format_list_response(true));
        assert_eq!(out[1], format_data_request(CF_UNICODETEXT));

        let mut data = encode_utf16("привет");
        // encode_utf16 уже добавляет завершающий NUL.
        assert_eq!(data.pop(), Some(0));
        let response = build_pdu(MSG_FORMAT_DATA_RESPONSE, FLAG_RESPONSE_OK, &data);
        assert!(process(&mut client, response).is_empty());
        assert_eq!(
            client.drain_events(),
            vec![ClipboardEvent::Text("привет".to_string())]
        );
    }

    #[test]
    fn remote_long_format_list_is_parsed() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, server_caps(GENERAL_FLAG_LONG_FORMAT_NAMES));
        let _ = process(&mut client, monitor_ready());
        let out = process(&mut client, format_list(&[CF_UNICODETEXT], true));
        assert_eq!(out[0], format_list_response(true));
        assert_eq!(out[1], format_data_request(CF_UNICODETEXT));
    }

    #[test]
    fn local_text_is_advertised_and_served() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, monitor_ready());

        let out = client.set_local_text(Some("hello".to_string()));
        let out = payloads(out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            parse_format_list(&out[0][HEADER_SIZE..], false),
            vec![CF_UNICODETEXT, CF_TEXT]
        );

        let request = build_pdu(MSG_FORMAT_DATA_REQUEST, 0, &CF_UNICODETEXT.to_le_bytes());
        let out = process(&mut client, request);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][2..4], &FLAG_RESPONSE_OK.to_le_bytes());
        assert_eq!(&out[0][HEADER_SIZE..], encode_utf16("hello").as_slice());
    }

    #[test]
    fn remote_to_local_can_be_disabled() {
        let mut client = CliprdrClient::new(config(true, false));
        let _ = process(&mut client, monitor_ready());
        let out = process(&mut client, format_list(&[CF_UNICODETEXT], false));
        assert_eq!(out, vec![format_list_response(true)]);
        assert!(client.pending_requests.is_empty());
    }

    #[test]
    fn rapid_format_lists_keep_request_order() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, monitor_ready());
        let _ = process(&mut client, format_list(&[CF_UNICODETEXT], false));
        let _ = process(&mut client, format_list(&[CF_UNICODETEXT], false));
        assert_eq!(client.pending_requests.len(), 2);

        for expected in ["first", "second"] {
            let response = build_pdu(
                MSG_FORMAT_DATA_RESPONSE,
                FLAG_RESPONSE_OK,
                &encode_utf16(expected),
            );
            assert!(process(&mut client, response).is_empty());
        }
        assert_eq!(
            client.drain_events(),
            vec![
                ClipboardEvent::Text("first".to_string()),
                ClipboardEvent::Text("second".to_string()),
            ]
        );
    }

    #[test]
    fn local_to_remote_can_be_disabled() {
        let mut client = CliprdrClient::new(config(false, true));
        let _ = process(&mut client, monitor_ready());
        assert!(client.set_local_text(Some("secret".to_string())).is_empty());

        let request = build_pdu(MSG_FORMAT_DATA_REQUEST, 0, &CF_UNICODETEXT.to_le_bytes());
        let out = process(&mut client, request);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][2..4], &FLAG_RESPONSE_FAIL.to_le_bytes());
    }

    #[test]
    fn unsupported_format_is_rejected() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, monitor_ready());
        let out = process(&mut client, format_list(&[0xC0F3], false));
        assert_eq!(out, vec![format_list_response(true)]);
        assert!(client.pending_requests.is_empty());
    }

    #[test]
    fn malformed_header_is_rejected() {
        let mut client = CliprdrClient::new(config(true, true));
        let result = client.process(b"short");
        assert!(result.is_err());
    }

    #[test]
    fn failed_response_with_bogus_length_is_accepted() {
        // gnome-remote-desktop может заявить dataLen > 0, не прислав данные.
        let mut pdu = build_pdu(MSG_FORMAT_DATA_RESPONSE, FLAG_RESPONSE_FAIL, &[]);
        pdu[4..8].copy_from_slice(&100u32.to_le_bytes());
        let mut client = CliprdrClient::new(config(true, true));
        assert!(process(&mut client, pdu).is_empty());
    }

    #[test]
    fn short_format_list_truncated_entry_is_ignored() {
        let mut data = Vec::new();
        data.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        assert!(parse_format_list(&data, false).is_empty());
    }

    #[test]
    fn unicode_response_strips_all_trailing_nuls() {
        let mut data = encode_utf16("abc");
        data.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_utf16(&data), "abc");
    }

    #[test]
    fn ansi_response_stops_at_nul() {
        assert_eq!(decode_ansi(b"hello\0tail"), "hello");
    }

    #[test]
    fn ansi_response_uses_windows_1252() {
        assert_eq!(decode_ansi(b"caf\xe9\0tail"), "café");
        assert_eq!(decode_ansi(b"\x80\0"), "€");
    }

    #[test]
    fn ansi_request_uses_windows_1252() {
        assert_eq!(
            encode_ansi("café €"),
            vec![b'c', b'a', b'f', 0xE9, b' ', 0x80, 0]
        );
        assert_eq!(encode_ansi("漢"), vec![b'?', 0]);
    }

    #[test]
    fn empty_local_text_clears_advertised_formats() {
        let mut client = CliprdrClient::new(config(true, true));
        let _ = process(&mut client, monitor_ready());
        let _ = client.set_local_text(Some("abc".to_string()));
        let out = payloads(client.set_local_text(Some(String::new())));
        assert_eq!(out.len(), 1);
        assert!(parse_format_list(&out[0][HEADER_SIZE..], false).is_empty());
    }

    #[test]
    fn malformed_caps_are_ignored() {
        let mut client = CliprdrClient::new(config(true, true));
        let pdu = build_pdu(MSG_CLIP_CAPS, 0, &[1, 0, 0, 0]);
        assert!(process(&mut client, pdu).is_empty());
        assert!(!client.server_long_names);
    }
}
