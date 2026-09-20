#!/bin/bash
# Подготовка исходников и сборка RPM-пакета remotix на РЕД ОС.
# Использование: ./make-rpm-sources.sh [путь-к-папке-remotix]
# Требуются: rpm-build, cargo, rust. Зависимости сборки ставятся автоматически.
set -euo pipefail

VERSION=1.0.0
PROJ_DIR="${1:-$(pwd)}"
cd "$PROJ_DIR"

echo "==> Установка зависимостей сборки (openssl-devel решает ошибку openssl-sys, gcc — сборку rusqlite bundled)..."
dnf install -y rpm-build cargo rust gcc gtk4-devel libssh2-devel \
               openssl-devel sqlite-devel || \
  sudo dnf install -y rpm-build cargo rust gcc gtk4-devel libssh2-devel \
               openssl-devel sqlite-devel

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
NAME=remotix-"$VERSION"

echo "==> Подготовка дерева исходников..."
cp -r . "$BUILD_DIR/$NAME"
cd "$BUILD_DIR/$NAME"
# vendor/ и .cargo/ пересоздаём заново: старый vendor может не соответствовать
# Cargo.toml, а закоммиченный .cargo/config.toml включает offline и блокирует
# обращение к crates.io во время cargo vendor.
rm -rf target .git vendor .cargo

echo "==> Заготовка vendor-каталога (офлайн-зависимости crates.io)..."
cargo vendor vendor > /dev/null

mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
EOF

echo "==> Создание архивов..."
mkdir -p ~/rpmbuild/SOURCES
tar -czf ~/rpmbuild/SOURCES/"$NAME".tar.gz -C "$BUILD_DIR" "$NAME"
tar -czf ~/rpmbuild/SOURCES/remotix-vendor-"$VERSION".tar.gz -C "$NAME" vendor
cp Cargo.lock ~/rpmbuild/SOURCES/

echo "==> Сборка RPM..."
rpmbuild -ba "$PROJ_DIR/packaging/remotix.spec"

echo
echo "Готово. Пакеты:"
ls -lh ~/rpmbuild/RPMS/*/remotix-*.rpm ~/rpmbuild/SRPMS/remotix-*.rpm
