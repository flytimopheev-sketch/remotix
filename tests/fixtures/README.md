# Фикстуры для тестов Standard RDP Security

Используются в `tests/rdpsec.rs` (подключаются через `include_bytes!`).

| Файл | Что это |
|------|---------|
| `rdp_v1_proprietary.bin` | `SERVER_CERTIFICATE` с `certChainVersion = 1` (проприетарный сертификат с ключом `RSA1`, 512-битный ключ, 184 байта). Байты взяты из эталонного `LICENSE_REQUEST` в `libxrdp/xrdp_sec.c` (xrdp). |
| `rdp_v1_expected.bin` | Шифртекст client random этим сертификатом (64 байта). |
| `rdp_v2_chain.bin` | Цепочка X.509 (`certChainVersion = 2`, 1598 байт): `dwVersion` (4) + `numCertBlobs` (4) + два блока `[длина (4)][DER]`. Терминальный сертификат — последний. |
| `rdp_v2_expected.bin` | Шифртекст client random ключом последнего сертификата цепочки (256 байт). |

Client random для эталонных шифртекстов:
`030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc`.

## Как получены

* Для v2 сгенерированы два независимых самоподписанных сертификата RSA-2048
  (`openssl req -x509 -newkey rsa:2048 ...`, затем `openssl x509 -outform DER`).
  Ключи разные, поэтому тест поймает выбор не того сертификата из цепочки.
* Эталонные шифртексты посчитаны независимо от Rust-кода в Python:
  `pow(int.from_bytes(client_random + b"\0" * (mod_len - 32), "little"), 65537, n)`,
  результат — в little-endian. Это та же схема без PKCS#1-паддинга, которую
  использует FreeRDP (`crypto_rsa_common`) и mstsc.
