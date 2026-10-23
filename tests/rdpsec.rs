//! Проверка криптодвижка Standard RDP Security (RC4), добавленного в
//! ironrdp-pdu патчем `third_party/ironrdp-pdu/src/rdpsec.rs`.
//!
//! Эталонные значения получены с эталонной реализацией, сверенной с живым
//! Windows TermService, поэтому тест ловит регрессии в расписании ключей,
//! MAC и потоке RC4 (в том числе продолжение keystream между PDU).

use ironrdp_pdu::rdpsec::{ENCRYPTION_FLAG_128BIT, ENCRYPTION_FLAG_40BIT, ENCRYPTION_FLAG_56BIT, RdpSecurity};

fn hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

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
