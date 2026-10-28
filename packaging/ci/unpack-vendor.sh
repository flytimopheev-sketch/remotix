#!/bin/bash
# Распаковка offline-зависимостей из vendor.tar.zst.
#
# vendor/ больше не хранится в git пофайлово (22 тыс. файлов, ~586 МБ):
# вместо него в репозитории один архив vendor.tar.zst. Свежий клон собирается
# офлайн после одной команды:
#
#   bash packaging/ci/unpack-vendor.sh
#
# cargo затем проверит контрольные суммы по .cargo-checksum.json — расхождение
# с Cargo.lock прервёт сборку, как и раньше.
#
# Пересобрать архив (в Docker с образом remotix-base, zstd в комплекте):
#   docker run --rm -v "$PWD:/work" -w /work remotix-base:latest \
#     tar --zstd -cf vendor.tar.zst vendor
set -euo pipefail

# Корень репозитория — на два уровня выше каталога скрипта (packaging/ci/).
cd "$(dirname "$0")/../.."

if [ -d vendor ] && [ -f vendor/.cargo-checksum.json ]; then
    echo "vendor/ уже распакован — ничего не делаю"
    exit 0
fi
[ -f vendor.tar.zst ] || { echo "vendor.tar.zst не найден" >&2; exit 1; }

command -v zstd >/dev/null 2>&1 || {
    echo "нужен zstd (dnf install zstd / apt install zstd)" >&2
    exit 1
}

echo "Распаковка vendor.tar.zst → vendor/"
tar --zstd -xf vendor.tar.zst
echo "vendor: $(ls vendor | wc -l) крейтов"
