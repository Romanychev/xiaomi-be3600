// internal/router/ssh.go
package router

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/romanychev/be3600/embedded"
	"github.com/romanychev/be3600/pkg/interfaces"
	"golang.org/x/crypto/ssh"
)

type SSHManager struct {
	clientConfig          *ssh.ClientConfig
	Client                *ssh.Client
	logWriter             interfaces.LogWriter
	logWriterWithProgress interfaces.LogWriterWithProgress
}

func NewSSHManager(
	logWriter interfaces.LogWriter,
	logWriterWithProgress interfaces.LogWriterWithProgress,
	password string,
) *SSHManager {

	return &SSHManager{
		clientConfig: &ssh.ClientConfig{
			User:            "root",
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Не для продакшена!
		},
		logWriter:             logWriter,
		logWriterWithProgress: logWriterWithProgress,
	}
}

func (sm *SSHManager) Connect(ip, sshPass string) (*ssh.Client, error) {
	client, err := ssh.Dial("tcp", ip+":22", sm.clientConfig)
	if err != nil {
		return nil, err
	}
	sm.Client = client
	return client, nil
}

type Response struct {
	Code int `json:"code"`
}

func (sm *SSHManager) EnableSSHPermanent(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to ssh connect: %v", err))
		return false
	}
	defer client.Close()

	if !sm.copyEmbeddedFileWithProgress(client, "Copying sing-box patch", embedded.SshPatch, "/etc/crontabs/patches/ssh_patch.sh") {
		return false
	}
	sm.logWriter.LogWrite("SSH patch installed to disk!")

	cmdR := "crontab -l > /tmp/current_crontab && if ! grep -q 'ssh_patch.sh' /tmp/current_crontab; then echo '*/1 * * * * /etc/crontabs/patches/ssh_patch.sh >/dev/null 2>&1' >> /tmp/current_crontab; crontab /tmp/current_crontab; fi"
	_, err = runSSHCommand(client, cmdR)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to add SSH check to cron: %v", err))
		return false
	}
	sm.logWriter.LogWrite("SSH installed!")

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}
	sm.logWriter.LogWrite("SSH login and script copied successfully.")
	defer client.Close()
	return true
}

func (sm *SSHManager) EnableSingboxPermanent(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to ssh connect: %v", err))
		return false
	}
	defer client.Close()

	if !sm.copyEmbeddedFileWithProgress(client, "Copying sing-box patch", embedded.SingBoxPatch, "/etc/crontabs/patches/singbox_patch.sh") {
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box patch installed to disk!"))

	cmdR := "crontab -l > /tmp/current_crontab && if ! grep -q 'singbox_patch.sh' /tmp/current_crontab; then echo '*/1 * * * * /etc/crontabs/patches/singbox_patch.sh >/dev/null 2>&1' >> /tmp/current_crontab; crontab /tmp/current_crontab; fi"
	_, err = runSSHCommand(client, cmdR)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to add singbox check to cron: %v.", err))
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box cron task installed!"))

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}

	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box patch installed successfully."))
	return true
}

func (sm *SSHManager) InstallSingBox(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login to router %s.", err.Error()))
		return false
	}
	defer client.Close()

	if _, err = runSSHCommand(client, "mkdir -p /data/sing-box"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error creating /data/sing-box: %s", err.Error()))
		return false
	}
	// Бинарник живёт в /data (флеш), а не в /tmp (tmpfs = RAM): оттуда он
	// маппится постранично и не съедает ~15 МБ памяти. Заливаем в .new и
	// подменяем через mv — так перезапись безопасна и при работающем сервисе.
	if !sm.copyEmbeddedFileWithProgress(client, "Copying sing-box binary", embedded.SingBoxBinary, "/data/sing-box/sing-box.new") {
		return false
	}
	if _, err = runSSHCommand(client, "mv /data/sing-box/sing-box.new /data/sing-box/sing-box"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error installing sing-box binary: %s", err.Error()))
		return false
	}
	if !sm.copyEmbeddedFileWithProgress(client, "Copying init.d file", embedded.SingBoxIni, "/etc/init.d/sing-box") {
		return false
	}
	if !sm.copyEmbeddedFileWithProgress(client, "Copying sing-box config", embedded.SingBoxConfig, "/data/sing-box/config.json") {
		return false
	}

	return true
}

func (sm *SSHManager) UninstallSingBox(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	// config.json в /data/sing-box намеренно не трогаем — переустановка
	// не должна терять пользовательский конфиг.
	removeFilesCmd := "rm -rf /tmp/sing-box /data/etc/sing-box /data/sing-box/sing-box /data/sing-box/sing-box.new /etc/init.d/sing-box /etc/crontabs/patches/singbox_patch.sh"
	_, err = runSSHCommand(client, removeFilesCmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error removing sing-box files: %s", err.Error()))
		return false
	}

	cmdRemove := "crontab -l > /tmp/current_crontab && sed -i '/singbox_patch.sh/d' /tmp/current_crontab && crontab /tmp/current_crontab && rm /tmp/current_crontab"
	_, err = runSSHCommand(client, cmdRemove)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error uninstall cron task for sing-box %s.", err.Error()))
		return false
	}

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}

	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box uninstall success!"))
	return true
}

func (sm *SSHManager) InstallSingBoxConfig(ip, password, config string, isContent bool) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	if strings.HasPrefix(config, "file://") {
		config = strings.TrimPrefix(config, "file://")
	}
	err = copyToRemote(client, config, "/data/sing-box/config.json", isContent)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error copying config file to router %s.", err.Error()))
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box config file copied to router success!."))
	return true
}

func (sm *SSHManager) ServiceOps(ip, password, service, command string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	_, err = runSSHCommand(client, service, command)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error %v, when sending command: %s, service %s", err.Error(), command, service))
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Service %s %s successful!.", service, command))
	return true
}

func (sm *SSHManager) InstallDnsBox(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login to router %s.", err.Error()))
		return false
	}
	defer client.Close()

	if _, err = runSSHCommand(client, "mkdir -p /data/dns-box"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error creating /data/dns-box: %s", err.Error()))
		return false
	}
	// Сервис работает прямо из /data/dns-box/dns-box, поэтому заливаем в
	// .new и подменяем через mv — перезапись безопасна и при работающем
	// процессе (он держит старый inode, "text file busy" не возникает).
	if !sm.copyEmbeddedFileWithProgress(client, "Copying dns-box binary", embedded.DnsBoxBinary, "/data/dns-box/dns-box.new") {
		return false
	}
	if _, err = runSSHCommand(client, "mv /data/dns-box/dns-box.new /data/dns-box/dns-box"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error installing dns-box binary: %s", err.Error()))
		return false
	}
	if !sm.copyEmbeddedFileWithProgress(client, "Copying dns-box init.d file", embedded.DnsBoxIni, "/etc/init.d/dns-box") {
		return false
	}
	if !sm.copyEmbeddedFileWithProgress(client, "Copying dns-box config", embedded.DnsBoxConfig, "/data/dns-box/config.json") {
		return false
	}

	if !sm.ChangeDnsMasqConfig(client, true) {
		return false
	}

	return true
}

func (sm *SSHManager) UninstallDnsBox(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	removeFilesCmd := "rm -rf /tmp/dns-box /data/dns-box /data/etc/dns-box /etc/init.d/dns-box /etc/crontabs/patches/dnsbox_patch.sh"
	_, err = runSSHCommand(client, removeFilesCmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error removing dns-box files: %s", err.Error()))
		return false
	}

	cmdRemove := "crontab -l > /tmp/current_crontab && sed -i '/dnsbox_patch.sh/d' /tmp/current_crontab && crontab /tmp/current_crontab && rm /tmp/current_crontab"
	_, err = runSSHCommand(client, cmdRemove)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error uninstall cron task for dns-box %s.", err.Error()))
		return false
	}

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}

	if !sm.ChangeDnsMasqConfig(client, false) {
		return false
	}

	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box uninstall success!"))
	return true
}

func (sm *SSHManager) EnableDnsBoxPermanent(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to ssh connect: %v", err))
		return false
	}
	defer client.Close()

	if !sm.copyEmbeddedFileWithProgress(client, "Copying dns-box patch", embedded.DnsBoxPatch, "/etc/crontabs/patches/dnsbox_patch.sh") {
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Dns-box patch installed to disk!"))

	cmdR := "crontab -l > /tmp/current_crontab && if ! grep -q 'dnsbox_patch.sh' /tmp/current_crontab; then echo '*/1 * * * * /etc/crontabs/patches/dnsbox_patch.sh >/dev/null 2>&1' >> /tmp/current_crontab; crontab /tmp/current_crontab; fi"
	_, err = runSSHCommand(client, cmdR)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to add dnsbox check to cron: %v.", err))
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("dns-box cron task installed!"))

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}

	sm.logWriter.LogWrite(fmt.Sprintf("Sing-box patch installed successfully."))
	return true
}

func (sm *SSHManager) FirewallPatchInstall(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to ssh connect: %v", err))
		return false
	}
	defer client.Close()

	if !sm.copyEmbeddedFileWithProgress(client, "Copying firewall patch", embedded.FirewallPatch, "/etc/crontabs/patches/firewall_patch.sh") {
		return false
	}

	// Без сброса маркера cron-задача выходит сразу и переустановленный патч
	// не перегенерирует firewall.sh до перезагрузки
	if _, err = runSSHCommand(client, "rm -f /tmp/firewall_patch.log"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to reset firewall patch marker: %v.", err))
		return false
	}

	cmdR := "crontab -l > /tmp/current_crontab && if ! grep -q 'firewall_patch.sh' /tmp/current_crontab; then echo '*/1 * * * * /etc/crontabs/patches/firewall_patch.sh >/dev/null 2>&1' >> /tmp/current_crontab; crontab /tmp/current_crontab; fi"
	_, err = runSSHCommand(client, cmdR)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to add firewall check to cron: %v.", err))
		return false
	}
	sm.logWriter.LogWrite(fmt.Sprintf("Firewall cron task installed!"))

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}
	sm.logWriter.LogWrite("Firewall patch installed successfully!")
	return true
}

func (sm *SSHManager) FirewallPatchUninstall(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to ssh connect: %v", err))
		return false
	}
	defer client.Close()

	removeFilesCmd := "rm -rf /data/userdisk/appdata/firewall.sh /etc/crontabs/patches/firewall_patch.sh"
	_, err = runSSHCommand(client, removeFilesCmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error removing dns-box files: %s", err.Error()))
		return false
	}

	cmdRemove := "crontab -l > /tmp/current_crontab && sed -i '/firewall_patch.sh/d' /tmp/current_crontab && crontab /tmp/current_crontab && rm /tmp/current_crontab"
	_, err = runSSHCommand(client, cmdRemove)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error uninstall task for firewall:  %s.", err.Error()))
		return false
	}

	err = sm.restartCron(client)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Failed to restart cron: %v", err))
		return false
	}

	sm.logWriter.LogWrite(fmt.Sprintf("Firewall uninstall success!"))
	return true

}

func (sm *SSHManager) FirewallReload(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	cmdRun := "/data/userdisk/appdata/firewall.sh reload"
	_, err = runSSHCommand(client, cmdRun)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error reloading firewall:  %s.", err.Error()))
		return false
	}
	sm.logWriter.LogWrite("Firewall reloaded successfully!")
	return true
}

// conntrackFlushCmd returns a shell fragment that deletes conntrack entries
// destined to every member of the given ipsets. Established connections
// (browser keep-alive, QUIC) are pinned to their old path: packets get
// remarked per-packet, but SNAT only applies to new conntrack entries, so
// rerouted old flows just hang until the client gives up. Dropping the
// entries forces an immediate reconnect over the new route. Prints
// CT_MISSING when the firmware has no conntrack tool.
func conntrackFlushCmd(sets ...string) string {
	cmd := "if command -v conntrack >/dev/null 2>&1; then "
	for _, set := range sets {
		family := ""
		if strings.HasSuffix(set, "6") {
			family = "-f ipv6 "
		}
		cmd += fmt.Sprintf(
			"ipset list %s 2>/dev/null | sed '1,/Members:/d' | awk '{print $1}' | while read -r e; do [ -n \"$e\" ] && conntrack %s-D -d \"$e\" >/dev/null 2>&1; done; ",
			set, family)
	}
	cmd += "echo CT_FLUSHED; else echo CT_MISSING; fi"
	return cmd
}

// bypassListPath is the user supplied IP/subnet bypass list; firewall.sh
// reloads it into the vpn_ips/vpn_ips6 ipsets on every reload, so the file
// is the source of truth that survives reboots.
const bypassListPath = "/data/userdisk/appdata/vpn_ips.txt"

func (sm *SSHManager) GetBypassList(ip, password string) (string, error) {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return "", err
	}
	defer client.Close()

	out, err := runSSHCommand(client, fmt.Sprintf("cat %s 2>/dev/null || true", bypassListPath))
	if err != nil {
		return "", fmt.Errorf("failed to read bypass list: %w", err)
	}
	return out, nil
}

func (sm *SSHManager) ApplyBypassList(ip, password, content string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	if _, err = runSSHCommand(client, "mkdir -p /data/userdisk/appdata"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error creating appdata dir: %s", err.Error()))
		return false
	}
	if err = copyToRemote(client, content, bypassListPath, true); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error copying bypass list to router: %s", err.Error()))
		return false
	}

	// Наполняем ipset'ы сразу, не дожидаясь перезагрузки; firewall.sh reload
	// (если патч установлен) добавит mangle-правила и маршрут в tun0.
	applyCmd := "ipset create vpn_ips hash:net -exist && " +
		"ipset create vpn_ips6 hash:net family inet6 -exist; " +
		"ipset flush vpn_ips; ipset flush vpn_ips6; " +
		"while IFS= read -r e; do [ -n \"$e\" ] || continue; case \"$e\" in *:*) ipset add vpn_ips6 \"$e\" -exist;; *) ipset add vpn_ips \"$e\" -exist;; esac; done < " + bypassListPath + "; " +
		"[ -x /data/userdisk/appdata/firewall.sh ] && /data/userdisk/appdata/firewall.sh reload; " +
		conntrackFlushCmd("vpn_ips", "vpn_ips6")
	out, err := runSSHCommand(client, applyCmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error applying bypass list: %s", err.Error()))
		return false
	}
	if strings.Contains(out, "CT_MISSING") {
		sm.logWriter.LogWrite("Note: conntrack tool not found on router, open connections keep the old route until they expire.")
	}

	sm.logWriter.LogWrite("Bypass list applied successfully!")
	return true
}

// MemInfo holds a snapshot of router RAM usage, all values in kilobytes.
// Used is memory that is neither free nor reclaimable cache/buffers, so
// Free + Used + Cached ≈ Total.
type MemInfo struct {
	Total  uint64
	Free   uint64
	Cached uint64
	Used   uint64
}

// GetMemInfo reads /proc/meminfo over its own SSH connection (it does not
// touch sm.Client, so it is safe to poll concurrently with other operations).
func (sm *SSHManager) GetMemInfo(ip, password string) (*MemInfo, error) {
	client, err := ssh.Dial("tcp", ip+":22", sm.clientConfig)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	if err := session.Run("cat /proc/meminfo"); err != nil {
		return nil, err
	}
	return parseMemInfo(buf.String())
}

func parseMemInfo(out string) (*MemInfo, error) {
	fields := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		fields[key] = val
	}
	total, ok := fields["MemTotal"]
	if !ok || total == 0 {
		return nil, fmt.Errorf("MemTotal not found in /proc/meminfo")
	}
	free := fields["MemFree"]
	cached := fields["Cached"] + fields["Buffers"]
	// classic "used": everything the kernel can't hand out on demand
	used := total - free - cached
	return &MemInfo{Total: total, Free: free, Cached: cached, Used: used}, nil
}

const dnsBoxConfigPath = "/data/dns-box/config.json"

// domainListPath is the persistent, editable domain list (same text format as
// the GUI: one domain per line, leading dot = suffix). It is the source of
// truth that survives dns-box reinstall/upgrade, which rewrites config.json
// with the embedded default — mirrors how bypassListPath persists IPs.
const domainListPath = "/data/userdisk/appdata/vpn_domains.txt"

func (sm *SSHManager) GetDomainList(ip, password string) (string, error) {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return "", err
	}
	defer client.Close()

	out, err := runSSHCommand(client, fmt.Sprintf("cat %s 2>/dev/null || true", domainListPath))
	if err != nil {
		return "", fmt.Errorf("failed to read domain list: %w", err)
	}
	return out, nil
}

func (sm *SSHManager) GetDnsBoxConfig(ip, password string) ([]byte, error) {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return nil, err
	}
	defer client.Close()

	out, err := sm.readRemoteFile(client, dnsBoxConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dns-box config (dns-box not installed?): %w", err)
	}
	return []byte(out), nil
}

// ApplyDnsBoxConfig writes the dns-box config and restarts the service.
// warmNames are then resolved through dnsmasq on the router itself: dns-box
// inflates answer TTLs to 5-60 min, so client and dnsmasq caches keep old
// answers long after a rule is added — pre-resolving fills the ipset with
// the destination IPs immediately, and routing works even for clients that
// still hold cached DNS answers.
func (sm *SSHManager) ApplyDnsBoxConfig(ip, password, content, domainListText string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	// dns-box на SIGTERM сохраняет свой in-memory конфиг обратно в
	// config.json, поэтому писать файл можно только после полной остановки —
	// иначе restart затирает свежезаписанный файл старым содержимым.
	stopCmd := "/etc/init.d/dns-box stop 2>/dev/null; i=0; while [ $i -lt 20 ] && pgrep dns-box >/dev/null 2>&1; do sleep 1; i=$((i+1)); done; pgrep dns-box >/dev/null 2>&1 && echo 'still-running'; true"
	out, err := runSSHCommand(client, stopCmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error stopping dns-box: %s", err.Error()))
		return false
	}
	if strings.Contains(out, "still-running") {
		sm.logWriter.LogWrite("Error: dns-box did not stop in 20s, config not applied.")
		return false
	}

	if err = copyToRemote(client, content, dnsBoxConfigPath, true); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error copying dns-box config to router: %s", err.Error()))
		// dns-box уже остановлен — поднимаем обратно со старым конфигом
		runSSHCommand(client, "/etc/init.d/dns-box", "start")
		return false
	}

	// Сохраняем список доменов отдельным файлом — источником истины, который
	// переживает переустановку dns-box (перезаписывающую config.json дефолтом).
	if _, mkErr := runSSHCommand(client, "mkdir -p /data/userdisk/appdata"); mkErr == nil {
		if wErr := copyToRemote(client, domainListText, domainListPath, true); wErr != nil {
			sm.logWriter.LogWrite(fmt.Sprintf("Warning: failed to save domain list file: %s", wErr.Error()))
		}
	}

	if _, err = runSSHCommand(client, "/etc/init.d/dns-box", "start"); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error starting dns-box: %s", err.Error()))
		return false
	}

	sm.logWriter.LogWrite("Domain list applied, dns-box restarted!")
	return true
}

func (sm *SSHManager) copyEmbeddedFileWithProgress(client *ssh.Client, description string, data []byte, remotePath string) bool {
	var copyErr error
	task := func() error {
		reader := bytes.NewReader(data)
		copyErr = copyBinaryToRemote(client, reader, int64(len(data)), remotePath, 0755)
		return copyErr
	}
	sm.logWriterWithProgress.LogWriteWithProgress(description, task)
	return copyErr == nil
}

func (sm *SSHManager) restartCron(client *ssh.Client) error {
	_, err := runSSHCommand(client, "/etc/init.d/cron restart")
	if err != nil {
		return err
	}
	sm.logWriter.LogWrite("Cron restarted successfully!")
	return nil
}

// dnsmasqPublicResolvers are the plain upstreams stock firmware leaves in
// /etc/config/dhcp. They must go while dns-box is active: with several
// `server` entries dnsmasq queries them in parallel and uses whoever answers
// first, so answers that bypass dns-box never populate the bypass ipset —
// the source of the intermittent "works after 10-15 min" behaviour.
var dnsmasqPublicResolvers = []string{"1.1.1.1", "8.8.8.8"}

var cachesizeRe = regexp.MustCompile(`option cachesize '\d+'`)

// buildDnsmasqModifications returns the regex→replacement edits for
// /etc/config/dhcp. On add, dns-box (127.0.0.1#953) becomes the sole upstream,
// noresolv is set, and the dnsmasq cache is disabled (cachesize 0) so every
// query reaches dns-box and keeps the bypass ipset populated. On remove, all
// of that is undone and the public resolvers are restored so stock DNS keeps
// working. Empty map means nothing to change.
func buildDnsmasqModifications(content string, add bool) map[string]string {
	mods := map[string]string{}
	var insertAfterHeader []string // lines to add right after "config dnsmasq"

	if add {
		if !strings.Contains(content, "option noresolv '1'") {
			mods[`(?m)(option resolvfile '\/tmp\/resolv\.conf\.d\/resolv\.conf\.auto')`] =
				"$1\n        option noresolv '1'"
		}
		if !strings.Contains(content, "list server '127.0.0.1#953'") {
			insertAfterHeader = append(insertAfterHeader, "        list server '127.0.0.1#953'")
		}
		for _, r := range dnsmasqPublicResolvers {
			if strings.Contains(content, "list server '"+r+"'") {
				mods[`(?m)^\s*list server '`+regexp.QuoteMeta(r)+`'\s*$`] = ""
			}
		}
		// dns-box populates the ipset only for queries it actually sees; a
		// dnsmasq cache in front of it would answer repeats itself and leave
		// the set empty after a dns-box restart or ipset timeout.
		if !strings.Contains(content, "option cachesize '0'") {
			if cachesizeRe.MatchString(content) {
				mods[`(?m)(option cachesize ')\d+(')`] = "${1}0${2}"
			} else {
				insertAfterHeader = append(insertAfterHeader, "        option cachesize '0'")
			}
		}
	} else {
		if strings.Contains(content, "option noresolv '1'") {
			mods[`(?m)^\s*option noresolv '1'\s*$`] = ""
		}
		if strings.Contains(content, "list server '127.0.0.1#953'") {
			mods[`(?m)^\s*list server '127\.0\.0\.1#953'\s*$`] = ""
		}
		// Убираем нашу правку кэша — dnsmasq вернётся к встроенному дефолту.
		if strings.Contains(content, "option cachesize '0'") {
			mods[`(?m)^\s*option cachesize '0'\s*$`] = ""
		}
		for _, r := range dnsmasqPublicResolvers {
			if !strings.Contains(content, "list server '"+r+"'") {
				insertAfterHeader = append(insertAfterHeader, "        list server '"+r+"'")
			}
		}
	}

	if len(insertAfterHeader) > 0 {
		mods[`(?m)(config dnsmasq)`] = "$1\n" + strings.Join(insertAfterHeader, "\n")
	}
	return mods
}

func (sm *SSHManager) ChangeDnsMasqConfig(client *ssh.Client, add bool) bool {
	filePath := "/etc/config/dhcp"
	currentContent, err := sm.readRemoteFile(client, filePath)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error reading file: %s", err))
		return false
	}

	patterns := buildDnsmasqModifications(currentContent, add)
	if len(patterns) == 0 {
		return true // уже в нужном состоянии
	}

	replacements := make(map[*regexp.Regexp]string)
	for pattern, replacement := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			sm.logWriter.LogWrite(fmt.Sprintf("Error compiling regex: %s", err))
			return false
		}
		replacements[re] = replacement
	}

	if err := sm.replaceRemoteFileRegex(client, filePath, replacements); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error updating: %s", err))
		return false
	}

	return true
}

func (sm *SSHManager) ConfigureVLAN(ip, password, vlanID string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	id := vlanID
	newReplacement := "." + id
	if id == "0" || id == "" {
		newReplacement = ""
	}

	fileModifications := map[string]map[string]string{
		"/etc/config/network": {
			`config interface 'eth1(\.\d+)?'`:      "config interface 'eth1'",
			`option ifname '([^']*?)eth1(\.\d+)?'`: "option ifname '${1}eth1" + newReplacement + "'",
		},
		"/etc/config/port_map": {
			`option ifname 'eth1(\.\d+)?'`: "option ifname 'eth1" + newReplacement + "'",
		},
	}

	for filePath, patterns := range fileModifications {
		replacements := make(map[*regexp.Regexp]string)
		for pattern, replacement := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				sm.logWriter.LogWrite(fmt.Sprintf("Error compiling regex: %s.", err.Error()))
				return false
			}
			replacements[re] = replacement
		}

		if err := sm.replaceRemoteFileRegex(client, filePath, replacements); err != nil {
			sm.logWriter.LogWrite(fmt.Sprintf("Error updating: %s", err.Error()))
		}
	}
	sm.logWriter.LogWrite(fmt.Sprintf("VLAN configuration updated successfully!"))
	return true
}

func (sm *SSHManager) ConfigureUART(ip, password string) bool {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return false
	}
	defer client.Close()

	fileModifications := map[string]map[string]string{
		"/etc/inittab": {
			`ttyMSM0::askfirst:/bin/ash\s+--login`: "ttyMSM0::askfirst:/bin/ash",
		},
	}

	for filePath, patterns := range fileModifications {
		replacements := make(map[*regexp.Regexp]string)
		for pattern, replacement := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				fmt.Println("Error compiling regex:", err)
				sm.logWriter.LogWrite(fmt.Sprintf("Error compiling regex: %s.\n", err.Error()))
				return false
			}
			replacements[re] = replacement
		}

		if err := sm.replaceRemoteFileRegex(client, filePath, replacements); err != nil {
			sm.logWriter.LogWrite(fmt.Sprintf("Error updating: %s", err))
			return false
		}
	}
	return true
}

type SingBoxInstaller struct {
	client *ssh.Client
}

func NewSingBoxInstaller(client *ssh.Client) *SingBoxInstaller {
	return &SingBoxInstaller{client: client}
}

func (si *SingBoxInstaller) Install() error {
	// Original installSingBox logic
	return nil
}

func copyBinaryToRemote(client *ssh.Client, reader io.Reader, size int64, remotePath string, mode os.FileMode) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	defer stdin.Close()

	remoteDir := filepath.Dir(remotePath)
	remoteDir = filepath.ToSlash(remoteDir)
	remoteFileName := filepath.Base(remotePath)

	mkdirSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create mkdir session: %w", err)
	}
	if output, err := mkdirSession.CombinedOutput(fmt.Sprintf("mkdir -p %s", strconv.Quote(remoteDir))); err != nil {
		mkdirSession.Close()
		return fmt.Errorf("failed to create remote directory: %s: %w", string(output), err)
	}
	mkdirSession.Close()

	if err := session.Start(fmt.Sprintf("scp -t %s", remoteDir)); err != nil {
		return fmt.Errorf("failed to start remote scp command: %w", err)
	}

	header := fmt.Sprintf("C%#o %d %s\n", mode.Perm()|0111, size, remoteFileName)
	if _, err := fmt.Fprint(stdin, header); err != nil {
		return fmt.Errorf("failed to send scp header: %w", err)
	}

	if _, err := io.Copy(stdin, reader); err != nil {
		return fmt.Errorf("failed to copy binary content: %w", err)
	}

	if _, err := fmt.Fprint(stdin, "\x00"); err != nil {
		return fmt.Errorf("failed to send scp end signal: %w", err)
	}

	stdin.Close()

	if err := session.Wait(); err != nil {
		return fmt.Errorf("remote scp command failed: %w", err)
	}

	return nil
}

// sshCommandTimeout bounds every remote command: init scripts on the router
// can block indefinitely (e.g. waiting for network or downloading updates),
// and without a deadline session.Run would hang forever.
const sshCommandTimeout = 5 * time.Minute

func runSSHCommand(client *ssh.Client, args ...string) (string, error) {
	if client == nil {
		return "", fmt.Errorf("client is nil")
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = os.Stderr
	cmd := exec.Command(args[0], args[1:]...)
	fmt.Println("COMMAND TO RUN:", cmd.String())

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd.String())
	}()
	select {
	case err := <-done:
		if err != nil {
			return stdoutBuf.String(), fmt.Errorf("failed to execute command: %w", err)
		}
		return stdoutBuf.String(), nil
	case <-time.After(sshCommandTimeout):
		session.Close()
		return "", fmt.Errorf("command %q timed out after %s", cmd.String(), sshCommandTimeout)
	}
}

func copyToRemote(client *ssh.Client, localPathOrContent, remotePath string, isContent bool) error {
	var srcFile *os.File
	var err error

	if isContent {
		srcFile = nil
	} else {
		srcFile, err = os.Open(localPathOrContent)
		if err != nil {
			return fmt.Errorf("failed to open local file: %w", err)
		}
		defer srcFile.Close()
	}

	var srcFileInfo os.FileInfo
	if !isContent {
		srcFileInfo, err = srcFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat local file: %w", err)
		}
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	pipe, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	defer pipe.Close()

	cmd := fmt.Sprintf("scp -t %s", remotePath)
	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("failed to start remote scp command: %w", err)
	}

	// Если передан файл, передаем его информацию
	if !isContent {
		fmt.Fprintf(pipe, "C%#o %d %s\n", srcFileInfo.Mode().Perm()|0111, srcFileInfo.Size(), filepath.Base(remotePath))

		if _, err := io.Copy(pipe, srcFile); err != nil {
			return fmt.Errorf("failed to copy file content: %w", err)
		}
	} else {
		// Если передан контент, передаем его напрямую в pipe
		fmt.Fprintf(pipe, "C%#o %d %s\n", 0644, len(localPathOrContent), filepath.Base(remotePath))

		if _, err := io.Copy(pipe, strings.NewReader(localPathOrContent)); err != nil {
			return fmt.Errorf("failed to copy content: %w", err)
		}
	}

	fmt.Fprint(pipe, "\x00")
	pipe.Close()

	if err := session.Wait(); err != nil {
		return fmt.Errorf("failed to complete scp command: %w", err)
	}

	return nil
}

// applyLineReplacements applies each regex to every line of content and
// returns the rewritten text plus whether anything changed. Matching is
// per-line, so patterns must target a single line.
func applyLineReplacements(content string, replacements map[*regexp.Regexp]string) (string, bool) {
	modified := false
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for re, replacement := range replacements {
			if re.MatchString(line) {
				newLine := re.ReplaceAllString(line, replacement)
				if line != newLine {
					lines[i] = newLine
					modified = true
				}
			}
		}
	}
	return strings.Join(lines, "\n"), modified
}

func (sm *SSHManager) replaceRemoteFileRegex(client *ssh.Client, filePath string, replacements map[*regexp.Regexp]string) error {
	cmd := fmt.Sprintf("cat %s", filePath)
	fileContent, err := runSSHCommand(client, cmd)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error running command: %s.", err.Error()))
	}

	updatedContent, modified := applyLineReplacements(fileContent, replacements)

	if !modified {
		fmt.Println("No changes needed for", filePath)
		sm.logWriter.LogWrite(fmt.Sprintf("No changes needed for %s", filePath))
		return nil
	}

	echoCommand := fmt.Sprintf("echo -e %q > %s", updatedContent, filePath)
	if _, err = runSSHCommand(client, echoCommand); err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("failed to update file: %v", err))
	}

	sm.logWriter.LogWrite("File updated successfully on remote host!")
	return nil
}

func (sm *SSHManager) readRemoteFile(client *ssh.Client, filePath string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	cmd := fmt.Sprintf("cat %s", filePath)

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to read file %s: %v", filePath, err)
	}

	return stdoutBuf.String(), nil
}

func (sm *SSHManager) ReadRemoteFile(filePath, ip, password string) (bytes.Buffer, error) {
	client, err := sm.Connect(ip, password)
	if err != nil {
		sm.logWriter.LogWrite(fmt.Sprintf("Error ssh login %s.", err.Error()))
		return bytes.Buffer{}, err
	}
	session, err := client.NewSession()
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	cmd := fmt.Sprintf("cat %s", filePath)

	if err := session.Run(cmd); err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}

	return stdoutBuf, nil
}
