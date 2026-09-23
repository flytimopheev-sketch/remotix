#!/bin/bash
# EL9-окружение для сборки RPM remotix — без Docker.
#
# Раньше пакет собирался в Docker-контейнере (container: almalinux:9) прямо в
# GitHub Actions. Docker больше не используется: тот же пользовательский
# уровень AlmaLinux 9 (EL9 — glibc 2.34, OpenSSL 3, GTK4 4.6) получается
# обычным chroot в rootfs AlmaLinux 9 с официального зеркала образов
# Linux Containers (rootfs.tar.xz). Бинарник, собранный в таком окружении,
# совместим с РЕД ОС 8 — как и при сборке в контейнере.
#
# Команды:
#   setup                        — скачать rootfs, примонтировать псевдо-ФС, поставить зависимости
#   run '<команда>'              — выполнить bash-команду внутри окружения
#   sh                           — выполнить bash-скрипт внутри окружения (читается со stdin)
#   copy-in  <хост> <в окружении> — скопировать каталог внутрь (.git/target/vendor/dist исключаются)
#   copy-out <в окружении> <хост> — скопировать каталог наружу
#   teardown                     — размонтировать псевдо-ФС
#
# Переменные окружения: EL9_ROOT (по умолчанию /opt/el9), EL9_MIRROR,
# EL9_FALLBACK_DATES (сборки rootfs на случай недоступности листинга зеркала).
set -euo pipefail

ROOT="${EL9_ROOT:-/opt/el9}"
MIRROR="${EL9_MIRROR:-https://images.linuxcontainers.org/images/almalinux/9/amd64/default}"
FALLBACK_DATES="${EL9_FALLBACK_DATES:-20260922_23:08 20260921_23:08 20260920_23:08}"
ROOTFS_ARCHIVE=/tmp/el9-rootfs.tar.xz
ROOTFS_WORK=/tmp/el9-rootfs.tar.xz.part

PKGS=(dnf-plugins-core epel-release rsync tar gzip xz which findutils)
BUILD_PKGS=(gcc make perl pkg-config
            gtk4-devel pango-devel cairo-devel cairo-gobject-devel
            gdk-pixbuf2-devel graphene-devel libepoxy-devel
            glib2-devel openssl-devel
            zlib-devel dejavu-sans-fonts
            rpm-build xorg-x11-server-Xvfb)

log() { printf '\n==> %s\n' "$*"; }

# Выполнить bash-команду внутри chroot с нормальным HOME/PATH.
inside() {
  sudo chroot "$ROOT" /bin/bash -c \
    "set -eo pipefail; export HOME=/root; export PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; $*"
}

# Список доступных сборок rootfs (свежие — первыми, известные даты — в конце).
rootfs_dates() {
  {
    curl -fsSL --retry 3 --max-time 60 "$MIRROR/" 2>/dev/null \
      | grep -oE '20[0-9]{6}_[0-9]{2}:[0-9]{2}' || true
    printf '%s\n' $FALLBACK_DATES
  } | sort -u | tac
}

cmd_setup() {
  if [ -x "$ROOT/bin/bash" ] && [ -d "$ROOT/usr/bin" ]; then
    log "Окружение EL9 уже развёрнуто: $ROOT"
  else
    log "Разворачивание rootfs AlmaLinux 9 в $ROOT (chroot, без Docker)"
    sudo mkdir -p "$ROOT" "$ROOT/tmp"
    local date url ok=0
    for date in $(rootfs_dates); do
      url="$MIRROR/$date/rootfs.tar.xz"
      printf '    пробую %s\n' "$url"
      if curl -fsSL --retry 3 --retry-delay 5 --max-time 900 -o "$ROOTFS_WORK" "$url"; then
        mv -f "$ROOTFS_WORK" "$ROOTFS_ARCHIVE"
        ok=1
        break
      fi
    done
    [ "$ok" = 1 ] || { echo "::error::не удалось скачать rootfs AlmaLinux 9"; exit 1; }
    sudo tar -xJf "$ROOTFS_ARCHIVE" -C "$ROOT"
    rm -f "$ROOTFS_ARCHIVE" "$ROOTFS_WORK"
  fi

  # Псевдо-ФС нужны dnf, rpmbuild и xvfb-run внутри chroot.
  sudo mkdir -p "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/run" "$ROOT/tmp"
  if ! mountpoint -q "$ROOT/proc"; then sudo mount --rbind /proc "$ROOT/proc"; fi
  if ! mountpoint -q "$ROOT/sys"; then sudo mount --rbind /sys "$ROOT/sys"; fi
  if ! mountpoint -q "$ROOT/dev"; then sudo mount --rbind /dev "$ROOT/dev"; fi
  # DNS внутри chroot (в LXC-rootfs resolv.conf ведёт в /run, которого нет).
  sudo rm -f "$ROOT/etc/resolv.conf"
  sudo cp -f /etc/resolv.conf "$ROOT/etc/resolv.conf"
  sudo chmod 644 "$ROOT/etc/resolv.conf"

  log "Зависимости окружения (dnf внутри EL9)"
  inside "dnf -y install ${PKGS[*]}"
  inside 'dnf config-manager --set-enabled crb'
  inside "dnf -y install --setopt=install_weak_deps=False ${BUILD_PKGS[*]}"

  log "Rust (stable) внутри окружения"
  inside 'curl -fsSL https://sh.rustup.rs -o /tmp/rustup.sh'
  inside 'sh /tmp/rustup.sh -y --profile minimal --default-toolchain stable'
  inside 'rm -f /tmp/rustup.sh'
  inside 'cargo --version && rustc --version'
  printf 'ОС внутри окружения: '; inside 'cat /etc/os-release | head -2'
}

cmd_run() {
  shift
  [ "$#" -gt 0 ] || { echo "usage: el9-chroot.sh run '<команда>'" >&2; exit 2; }
  inside "$*"
}

cmd_sh() {
  local host_script=/tmp/el9-step.sh
  # set -e переносим внутрь скрипта: он выполняется отдельным процессом bash.
  { echo 'set -euo pipefail'; cat; } > "$host_script"
  sudo cp -f "$host_script" "$ROOT/tmp/el9-step.sh"
  sudo chmod 755 "$ROOT/tmp/el9-step.sh"
  inside 'bash /tmp/el9-step.sh'
}

cmd_copy_in() {
  local src="${1:-}" dst="${2:-}"
  [ -n "$src" ] && [ -n "$dst" ] || { echo "usage: el9-chroot.sh copy-in <хост> <в окружении>" >&2; exit 2; }
  sudo mkdir -p "$ROOT$dst" "$ROOT/tmp"
  tar -C "$src" \
      --exclude=./.git --exclude=./target --exclude=./vendor \
      --exclude=./dist --exclude=./.kilo \
      -cf - . | sudo tar -C "$ROOT$dst" -xf -
}

cmd_copy_out() {
  local src="${1:-}" dst="${2:-}"
  [ -n "$src" ] && [ -n "$dst" ] || { echo "usage: el9-chroot.sh copy-out <в окружении> <хост>" >&2; exit 2; }
  mkdir -p "$dst"
  sudo tar -C "$ROOT$src" -cf - . | tar -C "$dst" -xf -
}

cmd_teardown() {
  local d
  for d in dev sys proc; do
    sudo umount -R "$ROOT/$d" 2>/dev/null || true
  done
}

case "${1:-}" in
  setup)    cmd_setup ;;
  run)      cmd_run "$@" ;;
  sh)       cmd_sh ;;
  copy-in)  cmd_copy_in "$2" "$3" ;;
  copy-out) cmd_copy_out "$2" "$3" ;;
  teardown) cmd_teardown ;;
  *) echo "usage: el9-chroot.sh {setup|run|sh|copy-in|copy-out|teardown}" >&2; exit 2 ;;
esac
