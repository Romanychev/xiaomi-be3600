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

wait_for_network() {
    n=0
    while [ "$n" -lt 30 ]; do
        ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && return 0
        n=$((n + 1))
        sleep 2
    done
    echo "[sing-box] Network wait timed out, continuing anyway..."
}

# Slim-бинарник (только vless) кладёт приложение be3600 в /tmp при
# установке — на /data ему часто не хватает места на флеше. После
# перезагрузки роутера /tmp пуст, и без переустановки из приложения
# сервис не поднимется. Из сети ничего не скачивается — единственный
# источник бинарника само приложение.
check_binary() {
    [ -x "$PROG" ] && return 0
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

# Выполняется под procd: проверяет бинарник, ждёт сеть и замещает себя sing-box'ом.
launch() {
    mkdir -p "$TMPDIR"
    stop_xiaomi_services
    check_binary || { sleep 10; exit 1; }
    wait_for_network
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
