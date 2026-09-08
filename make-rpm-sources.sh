#!/bin/bash
# Подготовка исходников и сборка RPM-пакета remotix на РЕД ОС.
# Использование: ./make-rpm-sources.sh [путь-к-папке-remotix]
# Требуются: rpm-build, cargo, rust. Зависимости сборки ставятся автоматически.
set -euo pipefail

VERSION=1.0.0
PROJ_DIR="${1:-$(pwd)}"
cd "$PROJ_DIR"

echo "==> Установка зависимостей сборки (в т.ч. openssl-devel — решает ошибку openssl-sys)..."
dnf install -y rpm-build cargo rust gtk4-devel libssh2-devel freerdp-devel \
               openssl-devel sqlite-devel || \
  sudo dnf install -y rpm-build cargo rust gtk4-devel libssh2-devel \
               freerdp-devel openssl-devel sqlite-devel

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
NAME=remotix-"$VERSION"

echo "==> Подготовка дерева исходников..."
cp -r . "$BUILD_DIR/$NAME"
cd "$BUILD_DIR/$NAME"
rm -rf target .git

echo "==> Заготовка vendor-каталога (офлайн-зависимости crates.io)..."
cargo vendor vendor > /dev/null

echo "==> Создание архивов..."
mkdir -p ~/rpmbuild/SOURCES
tar -czf ~/rpmbuild/SOURCES/"$NAME".tar.gz -C "$BUILD_DIR" "$NAME"
tar -czf ~/rpmbuild/SOURCES/remotix-vendor-"$VERSION".tar.gz -C "$NAME" vendor
cp Cargo.lock ~/rpmbuild/SOURCES/

echo "==> Сборка RPM..."
rpmbuild -ba "$PROJ_DIR/packaging/remotix.spec" \
  --define "_sourcedir $HOME/rpmbuild/SOURCES"

echo
echo "Готово. Пакеты:"
ls -lh ~/rpmbuild/RPMS/*/remotix-*.rpm ~/rpmbuild/SRPMS/remotix-*.rpm
