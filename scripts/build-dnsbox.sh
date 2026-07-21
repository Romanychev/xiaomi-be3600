#!/bin/sh
# Собирает dns-box из оригинальных исходников (github.com/crazytypewriter/dns-box)
# и кладёт результат в embedded/dnsbox/dns-box — тот самый бинарник, который
# приложение зашивает в себя и устанавливает на роутер в /data/dns-box.
#
# Без UPX — намеренно: упакованный ELF при старте распаковывает весь образ в
# анонимную память, а несжатый бинарник из /data (флеш) маппится постранично
# и почти не занимает RAM.
#
# Использование:
#   scripts/build-dnsbox.sh            # последний тег
#   scripts/build-dnsbox.sh v1.0.13    # конкретный тег/ветка/коммит
set -eu

REPO_URL="https://github.com/crazytypewriter/dns-box.git"
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT_DIR/embedded/dnsbox/dns-box"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

REF="${1:-}"
if [ -z "$REF" ]; then
    REF=$(git ls-remote --tags --refs "$REPO_URL" \
        | awk -F/ '{print $NF}' | sort -V | tail -n1)
    [ -n "$REF" ] || { echo "Failed to resolve latest dns-box tag" >&2; exit 1; }
fi
echo "==> Building dns-box $REF from $REPO_URL"

git clone --depth 1 --branch "$REF" "$REPO_URL" "$WORKDIR/dns-box"
cd "$WORKDIR/dns-box"

go mod tidy
GOOS=linux GOARCH=arm CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o dns-box ./cmd/dns-box/main.go

cp ./dns-box "$DEST"
chmod +x "$DEST"
echo "==> Done: $DEST ($(du -h "$DEST" | cut -f1), $REF)"
