#!/bin/sh

[ -e "/tmp/singbox_patch.log" ] && return 0

cat << 'EOF' > /etc/init.d/sing-box
#!/bin/sh /etc/rc.common
# start_service returns instantly: waiting for network happens inside the
# procd-supervised `launch` command, so boot is never blocked (Xiaomi stock
# firmware reboots the router via watchdog if an init script stalls the
# boot sequence).

START=99
USE_PROCD=1
EXTRA_COMMANDS="launch"

SCRIPT=/etc/init.d/sing-box
TMPDIR=/tmp/sing-box
DATADIR=/data/sing-box
# Бинарник (~17 МБ) не помещается на флеше /data на некоторых роутерах,
# поэтому живёт в /tmp (tmpfs = RAM): не персистентен и после перезагрузки
# роутера пропадает — check_binary() ниже про это и предупреждает.
# config.json маленький и остаётся на /data, чтобы пережить перезагрузку.
PROG=${TMPDIR}/sing-box
CONF=${DATADIR}/config.json
CHECKSUM=${DATADIR}/sing-box.sha256
GITHUB_RAW_BASE="https://raw.githubusercontent.com/Romanychev/xiaomi-be3600/main/embedded/singbox"

wait_for_network() {
    n=0
    while [ "$n" -lt 30 ]; do
        ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && return 0
        n=$((n + 1))
        sleep 2
    done
    echo "[sing-box] Network wait timed out, continuing anyway..."
}

# Slim-бинарник (только vless) кладёт приложение be3600 в /tmp при установке
# — на /data ему часто не хватает места на флеше. После перезагрузки роутера
# /tmp пуст, поэтому здесь же пытаемся сами скачать бинарник с GitHub —
# именно оттуда его и кладёт приложение (repo:
# github.com/Romanychev/xiaomi-be3600, файл embedded/singbox/sing-box).
# Скачанный файл обязательно сверяется с sha256, который приложение пишет
# в /data/sing-box/sing-box.sha256 при установке: без файла или при
# несовпадении скачанное не запускается — на роутере это код с правами root,
# доверять непроверенному скачанному бинарнику нельзя.
download_binary() {
    tmp="${TMPDIR}/sing-box.download"
    rm -f "$tmp"
    echo "[sing-box] Binary missing, trying to download from GitHub..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$tmp" "${GITHUB_RAW_BASE}/sing-box" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$tmp" "${GITHUB_RAW_BASE}/sing-box" 2>/dev/null
    else
        echo "[sing-box] Neither curl nor wget available, cannot auto-download."
        return 1
    fi
    if [ ! -s "$tmp" ]; then
        echo "[sing-box] Download failed."
        rm -f "$tmp"
        return 1
    fi
    if [ ! -f "$CHECKSUM" ]; then
        echo "[sing-box] No $CHECKSUM on this router, refusing to run unverified download."
        rm -f "$tmp"
        return 1
    fi
    expected=$(cat "$CHECKSUM")
    actual=$(sha256sum "$tmp" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        echo "[sing-box] Checksum mismatch (expected $expected, got $actual), refusing to run downloaded binary."
        rm -f "$tmp"
        return 1
    fi
    chmod +x "$tmp"
    mv "$tmp" "$PROG"
    echo "[sing-box] Downloaded and verified sing-box binary."
    return 0
}

check_binary() {
    [ -x "$PROG" ] && return 0
    download_binary && return 0
    echo "[sing-box] Binary not found at $PROG. Reinstall sing-box from the be3600 app."
    return 1
}

# Как только sing-box поднимет tun0, ставит маршрут и fwmark-правило для
# помеченного трафика. Нужен и при рестартах: удаление tun0 стирает маршрут.
install_tun_routes() {
    n=0
    while [ "$n" -lt 60 ]; do
        if ip link show tun0 >/dev/null 2>&1; then
            ip route replace default dev tun0 table 252
            ip -6 route replace default dev tun0 table 252 2>/dev/null
            ip rule list | grep -q "fwmark 0x2 lookup 252" || ip rule add fwmark 0x2 lookup 252
            ip -6 rule list 2>/dev/null | grep -q "fwmark 0x2 lookup 252" || ip -6 rule add fwmark 0x2 lookup 252 2>/dev/null
            return 0
        fi
        n=$((n + 1))
        sleep 2
    done
}

# Останавливает телеметрию/mesh-сервисы Xiaomi: trafficd и miio-агенты гонят
# статистику наружу и мешают туннелю, meshd-семейство роняет Wi-Fi при
# нестандартной конфигурации. disable переживает ребут, но после обновления
# прошивки сервисы возвращаются — поэтому гасим при каждом старте.
stop_xiaomi_services() {
    for svc in messagingagent.sh mosquitto miio_client xq_info_sync_mqtt \
               smartcontroller miot xqbc trafficd \
               miwifi-roam cab_meshd meshd topomon ssid_steering miwifi-discovery \
               netapi tbusd iweventd \
               syslog syslog-ng log; do
        [ -x "/etc/init.d/$svc" ] || continue
        "/etc/init.d/$svc" stop >/dev/null 2>&1
        "/etc/init.d/$svc" disable >/dev/null 2>&1
    done
    killall miwifi-discovery 2>/dev/null
    killall miwifi-roam 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    killall syslogd syslog-ng logd 2>/dev/null
    killall netapi tbusd 2>/dev/null
    killall iweventd.sh iwevent-call iwevent 2>/dev/null
    return 0
}

# Выполняется под procd: ждёт сеть (нужна на случай download_binary), проверяет
# бинарник и замещает себя sing-box'ом.
launch() {
    mkdir -p "$TMPDIR"
    stop_xiaomi_services
    wait_for_network
    check_binary || { sleep 10; exit 1; }
    install_tun_routes &
    # Ограничиваем кучу Go-рантайма: без лимита он неохотно отдаёт память
    # системе, а на роутере её ~176 МБ на всё.
    export GOMEMLIMIT=64MiB GOGC=50
    exec "$PROG" run -c "$CONF" -D "$TMPDIR"
}

start_service() {
    procd_open_instance
    procd_set_param command "$SCRIPT" launch
    procd_set_param limits core="unlimited"
    procd_set_param limits nofile="1000000 1000000"
    procd_set_param respawn 3600 10 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "sing-box"
}
EOF

chmod +x /etc/init.d/sing-box
/etc/init.d/sing-box enable
/etc/init.d/sing-box start
echo "singbox enabled" > /tmp/singbox_patch.log
