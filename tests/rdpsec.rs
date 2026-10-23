//! Проверка криптодвижка Standard RDP Security (RC4), добавленного в
//! ironrdp-pdu патчем `third_party/ironrdp-pdu/src/rdpsec.rs`.
//!
//! Эталонные значения получены с эталонной реализацией, сверенной с живым
//! Windows TermService, поэтому тест ловит регрессии в расписании ключей,
//! MAC и потоке RC4 (в том числе продолжение keystream между PDU).

use ironrdp_pdu::gcc::{EncryptionLevel, EncryptionMethod, ServerSecurityData};
use ironrdp_pdu::rdpsec::{
    encrypt_client_random, RdpSecurity, ENCRYPTION_FLAG_128BIT, ENCRYPTION_FLAG_40BIT,
    ENCRYPTION_FLAG_56BIT,
};
use ironrdp_pdu::{decode, encode_vec};

fn hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// Client random, для которого посчитаны эталонные шифртексты в
/// `tests/fixtures/` (см. `tests/fixtures/README.md`).
const CLIENT_RANDOM: [u8; 32] = [
    0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
    0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
];

/// Proprietary `SERVER_CERTIFICATE` (certChainVersion 1) с ключом `RSA1`.
const V1_CERT: &[u8] = include_bytes!("fixtures/rdp_v1_proprietary.bin");
const V1_EXPECTED: &[u8] = include_bytes!("fixtures/rdp_v1_expected.bin");

/// Цепочка X.509 (certChainVersion 2) длиннее прежнего лимита в 1024 байта;
/// терминальный сертификат — последний в цепочке.
const V2_CHAIN: &[u8] = include_bytes!("fixtures/rdp_v2_chain.bin");
const V2_EXPECTED: &[u8] = include_bytes!("fixtures/rdp_v2_expected.bin");

#[test]
fn differential_against_reference() {
    let c = [0x11u8; 32];
    let s = [0x22u8; 32];
    let pt = b"The quick brown fox jumps over the lazy dog";

    for (method, ct1, ct2, mac) in [
        (
            ENCRYPTION_FLAG_128BIT,
            "73ad9f310777d0ff56d1458a4f0f669d115f7c2ac2f4b36706f6fd94586a3b0dafb0f1866d663432f10ebf",
            "b84d7a0405ab",
            "fd0f1dc6ebd35d79",
        ),
        (
            ENCRYPTION_FLAG_40BIT | ENCRYPTION_FLAG_128BIT | ENCRYPTION_FLAG_56BIT,
            "c2931e1f6af814fedebb8d3a6f5843cd9c320a65b5fdf33796b66f8289d0930a04437054885a0dac2b96bb",
            "09395fcf6a56",
            "7966996ed0fa7cdc",
        ),
    ] {
        let mut sec = RdpSecurity::new(&c, &s, method);
        assert_eq!(sec.encrypt(pt), hex(ct1), "ct1 для метода {method:#04x}");
        assert_eq!(sec.encrypt(b"second"), hex(ct2), "ct2 для метода {method:#04x}");
        assert_eq!(
            RdpSecurity::new(&c, &s, method).mac(pt, None),
            hex(mac).as_slice(),
            "MAC для метода {method:#04x}"
        );
    }
}

#[test]
fn server_security_data_accepts_large_certificate() {
    // Сервер может прислать цепочку X.509 заметно длиннее прежнего лимита
    // в 1024 байта; декодер не должен её отвергать.
    let data = ServerSecurityData {
        encryption_method: EncryptionMethod::BIT_128,
        encryption_level: EncryptionLevel::High,
        server_random: Some([0x22; 32]),
        server_cert: V2_CHAIN.to_vec(),
    };

    let encoded = encode_vec(&data).unwrap();
    let decoded = decode::<ServerSecurityData>(&encoded).unwrap();

    assert_eq!(decoded.server_cert, V2_CHAIN);
}

#[test]
fn encrypt_client_random_proprietary_certificate() {
    assert_eq!(
        encrypt_client_random(V1_CERT, &CLIENT_RANDOM).unwrap(),
        V1_EXPECTED
    );
}

#[test]
fn encrypt_client_random_x509_chain() {
    assert!(V2_CHAIN.len() > 1024);
    assert_eq!(
        encrypt_client_random(V2_CHAIN, &CLIENT_RANDOM).unwrap(),
        V2_EXPECTED
    );
}

#[test]
fn encrypt_client_random_rejects_certificate_without_key() {
    let cert = vec![0u8; 2048];
    assert!(encrypt_client_random(&cert, &CLIENT_RANDOM).is_err());
}
