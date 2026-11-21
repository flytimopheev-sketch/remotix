# CONTEXT — Remotix

Живой документ проекта: архитектура, принятые решения, статус задач.
Хранится в репозитории, а не в песочнице агента (песочница эфемерна).

## Проект
- github.com/flytimopheev-sketch/remotix (MIT, ветка main).
- Клиент удалённого доступа для РЕД ОС: SSH, RDP, SFTP, VNC. Rust + GTK4, офлайн.
- Последний опубликованный релиз: v1.9.1 (18.11.2026). В main поверх него:
  a0b2822cf (NLA pubKeyAuth, TLS leftover, slow-path мышь) и a00e06965 (CLIPRDR, качество, полный экран).

## Стек
- Rust + gtk4-rs; рендер cairo ImageSurface, BgrA32 (совместим с cairo ARgb32 на LE).
- RDP: вендоренный IronRDP в third_party/ (pdu, session, connector, graphics).
  ironrdp-core не вендорен (crates.io), реэкспортится через `pub use ironrdp_core::*`.
- TLS: rustls. NLA/CredSSP: sspi (+ KDC по TCP/UDP/HTTP). Хранение: aes-gcm + argon2.
- Офлайн-сборка: vendor.tar.zst + packaging/ci/unpack-vendor.sh.

## Ключевые места кода
- src/protocols/rdp.rs — соединение, ввод, кадры, CLIPRDR.
  - connect_with(credssp, tls, legacy); security_modes() — лестница попыток.
  - extract_tls_server_public_key() — DER RSAPublicKey для CredSSP pubKeyAuth.
  - send_key — fast-path. send_mouse/send_wheel — см. решение №6 ниже.
  - write_input_frame → secure_outgoing_frame → queue_input → flush_outgoing.
  - flush_outgoing пишет в нижележащий поток (Framed не реализует io::Write),
    WouldBlock — не ошибка, остаток уходит на следующем шаге.
- src/ui/rdp_viewer.rs — DrawingArea в Overlay; Motion/GestureClick/Scroll;
  map_coordinates → rdp_screen::map_point.
- src/rdp_screen.rs — ScaleMode (Fit/OneToOne/Stretch), geometry(), map_point().
- third_party/ironrdp-session/src/active_stage.rs:
  - process_fastpath_input(image, events) — кодирует ввод И рисует курсор вimage.
  - secure_outgoing_frame: при security == None (TLS/NLA) — no-op.
  - ActiveStageOutput: ResponseFrame, GraphicsUpdate, PointerBitmap/Position/Hidden/Default,
    Terminate, DeactivateAll, MultitransportRequest, AutoDetect.
- DecodedImage::move_pointer / update_pointer — **pub(crate)**, из приложения недоступны.

## Принятые решения
1. Мышь: полные 16-битные pointerFlags. В fast-path они лежат в ТЕЛЕ
   TS_FP_INPUT_MOUSE_EVENT; 5-битный eventFlags заголовка выбирает только тип
   события. Прежний вывод «fast-path не выражает DOWN» был ошибочным.
2. TS_SECURITY_HEADER в MCS user_data писать нельзя (1.9.1): в TLS/NLA его нет,
   в RC4 обёртку добавляет secure_outgoing_frame. Лишние 4 байта → numEvents=0.
3. Slow-path ввод требует Share Control + Share Data Header (PDUTYPE2_INPUT) —
   добавлено в a0b2822cf.
4. Тесты кадров — разбором структуры, а не поиском байтов через windows(2).
5. Релиз только после зелёного CI на ветке (workflow_dispatch), затем FF main + тег.
6. **Курсор.** Единственный публичный путь отрисовки указателя —
   ActiveStage::process_fastpath_input: он вызывает image.move_pointer внутри себя.
   Ручная сборка кадров этот шаг пропускала, поэтому курсора в сессии не было видно
   («мышь не управляется») при_working_ вводе. Мышь и колесо переведены на
   process_fastpath_input; ручная сборка slow-path кадра удалена.
7. **Колесо.** GTK dy (±1) — это ЩЕЛЧКИ, а не единицы вращения. Один щелчок = 120
   (WHEEL_DELTA). wheel_rotation_units() переводит щелчки в единицы и ограничивает
   ±2 щелчка на PDU (9-битное поле [-256, 255]). Дробный dy не усекается в ноль.
8. **Рендеринг курсора — ТОЛЬКО программный (1.9.3).** Правка 1.9.2 (решение 6)
   была недостаточной: при pointer_software_rendering=false (Accelerated)
   библиотека отдаёт PointerBitmap наружу, DecodedImage::pointer остаётся None и
   move_pointer не рисует ничего — курсора нет даже через process_fastpath_input.
   connect_with включает pointer_software_rendering=true: серверные указатели
   рисуются в кадровый буфер (update_pointer), ввод мыши двигает их (move_pointer).
   Регрессионный тест server_pointer_rendered_and_client_input_moves_cursor
   фиксирует оба режима без сети (синтетический TS_COLORPOINTERATTRIBUTE,
   xor-маска 24bpp — декодер ожидает именно её).
9. **Кадр с курсором — без ожидания сервера.** Рисованный вводом курсор раньше
   уходил в UI только вместе с очередным кадром сервера: цикл сравнивал пиксели
   лишь после Ok(true). RdpConnection::image_dirty (take_image_dirty) помечает
   буфер после GraphicsUpdate от send_pointer_events/run, и цикл просмотра
   отправляет кадр и при Ok(false).
10. **Локальный курсор над удалённым экраном скрыт** (cursor "none" в
    rdp_viewer): виден ровно один указатель — тот, что рисует сессия,
    включая скрытый курсор и спецформы (I-beam, resize и т.д.).

## CI (.github/workflows/build-rpm.yml)
- Триггеры: push main, теги v*, workflow_dispatch (input publish_release).
- Quality gate: unpack vendor → apt (libgtk-4-dev, libssl-dev) → clippy --all-targets
  -D warnings → fmt --check → deny check.
- build-rpm: EL9 chroot (AlmaLinux 9) → сборка → юнит-тесты → smoke запуска → smoke GUI
  → ELF/glibc → rpmbuild → проверка RPM → artifact → attach к релизу по тегу.
- Грабли: rustfmt разбивает assert_eq! с кириллическим сообщением на несколько строк;
  clippy -D warnings ловит manual_range_contains (использовать (a..=b).contains(&x)).

## Статус задач
- [x] 1.9.1: убран TS_SECURITY_HEADER + строгий тест. CI зелёный, релиз опубликован.
- [x] NLA pubKeyAuth (a0b2822cf): ключ берётся из сертификата сервера.
- [x] Share Data Header в slow-path (a0b2822cf).
- [x] CLIPRDR, качество, полный экран (a00e06965).
- [x] 1.9.3 (2026-11-21): **мышь RDP починена полностью** — программный
      рендеринг курсора (решение 8) + image_dirty (решение 9) + скрытый
      локальный курсор (решение 10) + обновлённое оформление. Локальная
      проверка: cargo test 330/330, clippy -D warnings, fmt --check, скриншоты
      UI в Xvfb (светлая/Cosmic, диалог профиля). Оформление зафиксировано в
      CHANGELOG/spec/metainfo. Релиз-подтверждение на живом xrdp — за
      пользователем.
- [ ] Аппаратный курсор GTK (отрисовка PointerBitmap через gdk::Cursor) —
      возможное будущее улучшение: курсор двигался бы без перерисовки кадра.
      Сейчас не нужно: программный курсор обновляется в момент ввода.
- [ ] 10.252.1.66:3389 — ECONNREFUSED: проблема хоста (xrdp не слушает / firewall).
- [ ] Список оставшихся пунктов улучшений от заказчика НЕ получен.

## Ограничения среды агента
- rustc/cargo можно поставить локально (rustup, static.rust-lang.org доступен);
  GTK4-заголовки ставятся без root: apt-get download libgtk-4-dev + цепочка
  зависимостей, dpkg -x в ~/gtkroot, PKG_CONFIG_PATH на
  ~/gtkroot/usr/lib/x86_64-linux-gnu/pkgconfig. Линковка — RUSTFLAGS
  "-L ~/gtkroot/usr/lib/x86_64-linux-gnu", запуск — LD_LIBRARY_PATH туда же.
  GTK4 4.18 (trixie) собирает проект без ошибок.
- Скриншоты UI: Xvfb (apt-get download xvfb xauth x11-apps x11-utils xdotool
  libxdo3 libxtst6 → ~/gtkroot), GSK_RENDERER=cairo (GL в Xvfb рисует пустые
  окна), REMOTIX_MASTER_PASSWORD=test, xwd -id <окно> + scripts/xwd2png.py
  (XWD = 25 полей, bpp 24/32, пиксели после header_size + ncolors*12).
  Значки Adwaita не грузятся (нет pixbuf-SVG) — это артефакт песочницы.
- vendor/ (372 крейта) распаковывается packaging/ci/unpack-vendor.sh; сборка
  офлайн через .cargo/config.toml. Диск: target/ ~5 ГБ — следить за местом.
