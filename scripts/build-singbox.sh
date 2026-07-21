#!/bin/sh
# Собирает slim-версию sing-box из оригинальных исходников (SagerNet/sing-box)
# и кладёт результат в embedded/singbox/sing-box.
#
# Slim = кастомная точка входа cmd/sing-box-slim: берутся оригинальные
# main.go/cmd.go/cmd_run.go/cmd_check.go/cmd_version.go, а пакет include
# заменяется на scripts/singbox-slim/slim_include.go, где зарегистрированы
# только используемые компоненты (tun/mixed входы, vless/direct/selector/
# urltest выходы). vmess/trojan/ss/hysteria/tuic/wireguard/clash-api и прочее
# линкер выбрасывает: 15 МБ вместо 31 МБ.
#
# Без UPX — намеренно: бинарник живёт в /tmp роутера (tmpfs = RAM), и
# упакованный ELF при старте распаковывает весь образ в анонимную память
# (7 МБ файл + ~31 МБ образ). Неупакованный маппится из tmpfs без
# дублирования: ~15 МБ суммарно.
#
# Использование:
#   scripts/build-singbox.sh            # последний тег
#   scripts/build-singbox.sh v1.12.15   # конкретный тег/ветка/коммит
set -eu

REPO_URL="https://github.com/SagerNet/sing-box.git"
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT_DIR/embedded/singbox/sing-box"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

REF="${1:-}"
if [ -z "$REF" ]; then
    REF=$(git ls-remote --tags --refs "$REPO_URL" \
        | awk -F/ '{print $NF}' | grep -v -- '-' | sort -V | tail -n1)
    [ -n "$REF" ] || { echo "Failed to resolve latest sing-box tag" >&2; exit 1; }
fi
echo "==> Building sing-box $REF (slim, vless-only) from $REPO_URL"

git clone --depth 1 --branch "$REF" "$REPO_URL" "$WORKDIR/sing-box"
cd "$WORKDIR/sing-box"

# Собираем slim-вход: оригинальные cmd-файлы + наш реестр вместо include.
mkdir -p cmd/sing-box-slim
cp cmd/sing-box/main.go cmd/sing-box/cmd.go cmd/sing-box/cmd_run.go \
   cmd/sing-box/cmd_check.go cmd/sing-box/cmd_version.go cmd/sing-box-slim/
# Тег ignore исключает файл из сборки самого be3600 — здесь срезаем его.
sed 's|^//go:build ignore$||' "$ROOT_DIR/scripts/singbox-slim/slim_include.go" \
    > cmd/sing-box-slim/slim_include.go
sed -i.bak \
    -e 's|"github.com/sagernet/sing-box/include"||' \
    -e 's|include\.Context(|slimContext(|' \
    cmd/sing-box-slim/cmd.go
rm cmd/sing-box-slim/cmd.go.bak
grep -q slimContext cmd/sing-box-slim/cmd.go || {
    echo "Failed to patch cmd.go: include.Context call not found (upstream changed?)" >&2
    exit 1
}

VERSION=${REF#v}
GOOS=linux GOARCH=arm CGO_ENABLED=0 \
    go build -trimpath \
    -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$VERSION' -s -w -buildid=" \
    -tags with_utls -o sing-box ./cmd/sing-box-slim

cp ./sing-box "$DEST"
chmod +x "$DEST"
echo "==> Done: $DEST ($(du -h "$DEST" | cut -f1), $REF)"
