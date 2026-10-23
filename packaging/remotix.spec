Name:           remotix
Version:        1.5.4
Release:        1%{?dist}
Summary:        Клиент удалённого доступа (RDP/VNC/SSH) для РЕД ОС
License:        MIT
URL:            https://github.com/flytimopheev-sketch/remotix
Source0:        %{name}-%{version}.tar.gz
# Tarball с зависимостями crates.io: cargo vendor vendor (готовится один раз
# на машине с интернетом), чтобы сборка на РЕД ОС шла полностью офлайн.
Source1:        %{name}-vendor-%{version}.tar.gz

# Отдельный debuginfo-пакет не нужен: бинарник и так небольшой.
%global debug_package %{nil}

BuildRequires:  gcc
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pkg-config
BuildRequires:  gtk4-devel
BuildRequires:  libssh2-devel
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
# Примечание: VTE для GTK4 в сборке не нужен — терминал подгружает
# libvte-2.91-gtk4.so.0 динамически (libloading) и работает без него.
# Примечание: freerdp-devel больше не нужен — RDP через IronRDP (чистый Rust,
# все зависимости вендорятся в vendor/). Системный openssl используется только
# для libssh2; rustls (ring) для RDP-канала — полностью офлайн.

Requires:       gtk4
# Модуль SSH линкуется с системной libssh2 (crate ssh2) — она нужна в рантайме.
Requires:       libssh2
# VTE для GTK4 опционален: с ним SSH-терминал получает полную эмуляцию
# (ANSI, vim/htop), без него используется встроенный упрощённый терминал.
Recommends:     vte291-gtk4

%description
Единый интерфейс для подключения к удалённым рабочим столам и серверам
по протоколам RDP, VNC и SSH, аналог Remmina/RustDesk. Работает полностью
офлайн, без облака и телеметрии. Учётные данные хранятся зашифрованными
(Argon2id + AES-256-GCM). SSH-терминал использует VTE для GTK4, если он
установлен в системе, иначе — встроенный упрощённый терминал.

%prep
rm -rf %{_builddir}/%{name}-%{version}
mkdir -p %{_builddir}/%{name}-%{version}
tar -xzf %{SOURCE0} -C %{_builddir}/%{name}-%{version} --strip-components=1
tar -xzf %{SOURCE1} -C %{_builddir}/%{name}-%{version}
cp %{_sourcedir}/Cargo.lock %{_builddir}/%{name}-%{version}/Cargo.lock 2>/dev/null || true
chmod -Rf a+rX,u+w,g-w,o-w %{_builddir}/%{name}-%{version}

%build
cd %{_builddir}/%{name}-%{version}
cargo build --release --offline

%install
cd %{_builddir}/%{name}-%{version}
install -Dm755 target/release/remotix %{buildroot}%{_bindir}/remotix
install -Dm644 packaging/remotix.desktop %{buildroot}%{_datadir}/applications/remotix.desktop
install -Dm644 resources/icons/remotix.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/remotix.svg
install -Dm644 packaging/remotix.metainfo.xml %{buildroot}%{_datadir}/metainfo/remotix.metainfo.xml
install -Dm644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_bindir}/remotix
%{_datadir}/applications/remotix.desktop
%{_datadir}/icons/hicolor/scalable/apps/remotix.svg
%{_datadir}/metainfo/remotix.metainfo.xml

%changelog
* Fri Oct 23 2026 Remotix Team <flytimopheev@gmail.com> - 1.5.4
- SFTP: вход в каталоги на серверах, не сообщающих тип объекта в атрибутах
  (проверка по opendir, канонизация пути через realpath)
- SFTP: верные значки папок и сортировка «сначала каталоги» на таких серверах
- RDP: уточнённое сообщение для серверов только со Standard RDP Security
* Thu Oct 22 2026 Remotix Team <flytimopheev@gmail.com> - 1.5.3
- Строка состояния больше не растягивает окно: фиксированная ширина метки,
  текст обрезается многоточием, полный — во всплывающей подсказке
- SFTP: переходы по каталогам работают и на серверах, не отдающих права
  объектов; ошибка «не каталог» показывается явно
- SFTP: сочетания клавиш как в терминале — Ctrl+C (копировать), Ctrl+V
  (вставить), Delete (удалить)
- RDP: понятная подсказка, если сервер умеет только Standard RDP Security
* Thu Oct 22 2026 Remotix Team <flytimopheev@gmail.com> - 1.5.2
- RDP: окно больше не расширяется по ширине (экран рисуется в области
  отрисовки с нулевым минимальным размером и масштабируется под окно)
- Боковую панель нельзя свернуть совсем (минимальная ширина 200 пикселей)
- В сообщении об ошибке RDP подсказка «на порту отвечает не RDP-сервер»
  теперь в начале текста
* Thu Oct 22 2026 Remotix Team <flytimopheev@gmail.com> - 1.5.1
- SFTP: исправлен вход в каталоги на сервере (было «[SFTP(2)] no such file»)
- RDP: перебор вариантов защиты (NLA, NLA+TLS, TLS) и понятное сообщение
  об ошибке с проверкой, что на порту отвечает именно RDP-сервер
* Thu Oct 22 2026 Remotix Team <flytimopheev@gmail.com> - 1.5.0
- SFTP: список снова листается стрелками, выделение не сбрасывается при
  автообновлении каталога
- Правый клик по профилю больше не выбрасывает программу
- Удаление профиля больше не падает с «FOREIGN KEY constraint failed»
- RDP: окно не раздувается по ширине, исправлен обмен токенами NLA (CredSSP)
- Порт в редакторе профиля больше не сбрасывается на стандартный
* Wed Oct 21 2026 Remotix Team <flytimopheev@gmail.com> - 1.4.0
- Исправлен запуск графического интерфейса в РЕД ОС: приложение больше не
  завершается с «GLib-GIO-CRITICAL: This application can not open files»
- Мастер-пароль запрашивается до показа главного окна (диалог привязан к
  приложению и больше не закрывает его)
- Рабочий список профилей, редактор подключений, поиск и горячие клавиши
* Mon Sep 07 2026 Remotix Team <flytimopheev@gmail.com> - 1.4.0
- Первый выпуск: RDP/VNC/SSH, SFTP, шифрование, история подключений
