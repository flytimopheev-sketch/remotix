Name:           remotix
Version:        1.0.0
Release:        1%{?dist}
Summary:        Клиент удалённого доступа (RDP/VNC/SSH) для РЕД ОС
License:        MIT
URL:            https://redos.example/remotix
Source0:        %{name}-%{version}.tar.gz
# Tarball с зависимостями crates.io: cargo vendor vendor (готовится один раз
# на машине с интернетом), чтобы сборка на РЕД ОС шла полностью офлайн.
Source1:        %{name}-vendor-%{version}.tar.gz
Source2:        Cargo.lock

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gtk4-devel
BuildRequires:  libssh2-devel
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
# Примечание: freerdp-devel больше не нужен — RDP через IronRDP (чистый Rust,
# все зависимости вендорятся в vendor/). Системный openssl используется только
# для libssh2; rustls (ring) для RDP-канала — полностью офлайн.

Requires:       gtk4
Requires:       libssh2

%description
Единый интерфейс для подключения к удалённым рабочим столам и серверам
по протоколам RDP, VNC и SSH, аналог Remmina/RustDesk. Работает полностью
офлайн, без облака и телеметрии. Учётные данные хранятся зашифрованными
(Argon2id + AES-256-GCM).

%prep
%setup -q -n %{name}-%{version} -a 1
cp %{SOURCE2} .
# end of prep
%build
# Полностью офлайн-сборка: крейты берутся из vendor/, системные библиотеки
# (gtk4-devel, libssh2-devel, freerdp-devel, openssl-devel) — из офлайн-
# репозитория РЕД ОС. Ничего не скачивается из интернета.
cargo build --release --offline

%install
install -Dm755 target/release/remotix %{buildroot}/usr/bin/remotix
install -Dm644 packaging/remotix.desktop %{buildroot}/usr/share/applications/remotix.desktop
install -Dm644 resources/icons/remotix.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/remotix.svg
install -Dm644 packaging/remotix.metainfo.xml %{buildroot}/usr/share/metainfo/remotix.metainfo.xml

%files
/usr/bin/remotix
/usr/share/applications/remotix.desktop
/usr/share/icons/hicolor/scalable/apps/remotix.svg
/usr/share/metainfo/remotix.metainfo.xml

%changelog
* Mon Sep 07 2026 Remotix Team <dev@redos.example> - 1.0.0
- Первый выпуск: RDP/VNC/SSH, SFTP, шифрование, история подключений
