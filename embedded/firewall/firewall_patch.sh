#!/bin/sh

[ -e "/tmp/firewall_patch.log" ] && exit 0

cat << 'EOF' > /data/userdisk/appdata/firewall.sh
#!/bin/sh
# Routes traffic marked by ipset match into sing-box's tun0.
# Table 252 matches iproute2_table_index in the sing-box config.

TABLE=252
MARK=0x2
USER_IPS=/data/userdisk/appdata/vpn_ips.txt

# Пользовательский список IP/подсетей для обхода: hash:net принимает и
# одиночные адреса, и CIDR; файл — источник истины, сеты пересобираются
# при каждом reload, поэтому удалённые записи пропадают.
load_user_ips() {
    ipset create vpn_ips hash:net -exist
    ipset create vpn_ips6 hash:net family inet6 -exist 2>/dev/null
    ipset flush vpn_ips
    ipset flush vpn_ips6 2>/dev/null
    [ -f "$USER_IPS" ] || return 0
    while IFS= read -r entry; do
        entry=${entry%%#*}
        entry=$(echo "$entry" | tr -d ' \t\r')
        [ -n "$entry" ] || continue
        case "$entry" in
            *:*) ipset add vpn_ips6 "$entry" -exist 2>/dev/null ;;
            *)   ipset add vpn_ips "$entry" -exist 2>/dev/null ;;
        esac
    done < "$USER_IPS"
}

install_routes() {
    # tun0 появляется асинхронно (sing-box стартует под procd и поднимает
    # интерфейс уже после того, как launch() дождётся сети), поэтому патч,
    # применённый сразу после установки/запуска sing-box, может застать
    # интерфейс ещё не поднятым — ждём как install_tun_routes в самом
    # sing-box init-скрипте, а не падаем с первой попытки.
    n=0
    while [ "$n" -lt 30 ] && ! ip link show tun0 >/dev/null 2>&1; do
        n=$((n + 1))
        sleep 2
    done
    # Без маршрута в таблице fwmark-правило никуда не ведёт и трафик уходит в WAN
    if ip link show tun0 >/dev/null 2>&1; then
        ip route replace default dev tun0 table $TABLE
        ip -6 route replace default dev tun0 table $TABLE 2>/dev/null
    else
        echo "Error: tun0 is not up (sing-box not running?), route not installed" >&2
        return 1
    fi
    # Матчим только по "fwmark $MARK ", без "lookup $TABLE": `ip rule list`
    # печатает таблицу по имени из /etc/iproute2/rt_tables (например "vpn"),
    # если оно там определено для этого номера, а не по номеру — сравнение с
    # "lookup $TABLE" тогда никогда не совпадает, и правило добавляется
    # заново при каждом reload, бесконечно накапливая дубликаты.
    ip rule list | grep -q "fwmark $MARK " || ip rule add fwmark $MARK lookup $TABLE
    ip -6 rule list 2>/dev/null | grep -q "fwmark $MARK " || ip -6 rule add fwmark $MARK lookup $TABLE 2>/dev/null
    return 0
}

reload() {
    install_routes || return 1

    load_user_ips

    iptables -t mangle -C PREROUTING -m set --match-set vpn_ips dst -j MARK --set-mark $MARK 2>/dev/null || iptables -t mangle -A PREROUTING -m set --match-set vpn_ips dst -j MARK --set-mark $MARK
    iptables -t mangle -C OUTPUT -m set --match-set vpn_ips dst -j MARK --set-mark $MARK 2>/dev/null || iptables -t mangle -A OUTPUT -m set --match-set vpn_ips dst -j MARK --set-mark $MARK
    iptables -C FORWARD -m mark --mark $MARK -j ACCEPT 2>/dev/null || iptables -I FORWARD -m mark --mark $MARK -j ACCEPT
    iptables -t nat -C POSTROUTING -o tun0 -j SNAT --to-source 172.16.250.1 2>/dev/null || iptables -t nat -A POSTROUTING -o tun0 -j SNAT --to-source 172.16.250.1

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t mangle -C PREROUTING -m set --match-set vpn_ips6 dst -j MARK --set-mark $MARK 2>/dev/null || ip6tables -t mangle -A PREROUTING -m set --match-set vpn_ips6 dst -j MARK --set-mark $MARK
        ip6tables -t mangle -C OUTPUT -m set --match-set vpn_ips6 dst -j MARK --set-mark $MARK 2>/dev/null || ip6tables -t mangle -A OUTPUT -m set --match-set vpn_ips6 dst -j MARK --set-mark $MARK
        ip6tables -C FORWARD -m mark --mark $MARK -j ACCEPT 2>/dev/null || ip6tables -I FORWARD -m mark --mark $MARK -j ACCEPT
    fi

    # dns-box создаёт ipset при своём старте, который тоже асинхронный
    # (procd + собственный wait_for_network) — та же гонка, что и с tun0 выше.
    n=0
    while [ "$n" -lt 30 ] && ! ipset list vpn_domains >/dev/null 2>&1; do
        n=$((n + 1))
        sleep 2
    done
    if ! ipset list vpn_domains >/dev/null 2>&1; then
        echo "Error: ipset vpn_domains does not exist (dns-box not running?)" >&2
        return 1
    fi

    iptables -t mangle -C PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark $MARK 2>/dev/null || iptables -t mangle -A PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark $MARK
    iptables -t mangle -C OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark $MARK 2>/dev/null || iptables -t mangle -A OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark $MARK

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t mangle -C PREROUTING -m set --match-set vpn_domains6 dst -j MARK --set-mark $MARK 2>/dev/null || ip6tables -t mangle -A PREROUTING -m set --match-set vpn_domains6 dst -j MARK --set-mark $MARK
        ip6tables -t mangle -C OUTPUT -m set --match-set vpn_domains6 dst -j MARK --set-mark $MARK 2>/dev/null || ip6tables -t mangle -A OUTPUT -m set --match-set vpn_domains6 dst -j MARK --set-mark $MARK
    fi

    return 0
}

case "$1" in
    reload)
        reload
        ;;
    *)
        echo "plugin_firewall: not support cmd: $1"
        ;;
esac
EOF

chmod +x /data/userdisk/appdata/firewall.sh

if /data/userdisk/appdata/firewall.sh reload; then
    echo "firewall enabled" > /tmp/firewall_patch.log
else
    echo "firewall reload failed; not creating /tmp/firewall_patch.log" >&2
    exit 1
fi
