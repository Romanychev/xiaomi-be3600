package app

import (
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"github.com/romanychev/be3600/embedded"
	"github.com/romanychev/be3600/internal/gui"
	"github.com/romanychev/be3600/internal/router"
	"github.com/romanychev/be3600/internal/services"
	"github.com/rushysloth/go-tsid"
)

type AppWindow struct {
	Window        fyne.Window
	UI            *gui.Components
	SSHClient     *router.SSHManager
	Services      *services.NetworkService
	AuthClient    *router.AuthClient
	ConfigManager *services.ConfigManager

	busy             atomic.Bool
	ramPollerStarted atomic.Bool
}

// runTask executes a long operation (SSH, HTTP) on a background goroutine so
// the UI stays responsive, and rejects a second operation while one is running.
func (aw *AppWindow) runTask(task func()) {
	if !aw.busy.CompareAndSwap(false, true) {
		aw.LogWrite("Another operation is still running, please wait...")
		return
	}
	go func() {
		defer aw.busy.Store(false)
		task()
	}()
}

func (aw *AppWindow) requireSSH() bool {
	if aw.SSHClient == nil {
		aw.LogWrite("Router is not detected yet, enter the router IP first.")
		return false
	}
	return true
}

func NewAppWindow(app fyne.App) *AppWindow {
	aw := &AppWindow{
		Window:        app.NewWindow("Xiaomi BE3600 Tool"),
		UI:            gui.NewComponents(),
		Services:      services.NewNetworkService(),
		AuthClient:    router.NewAuthClient(nil),
		ConfigManager: services.NewConfigManager(),
	}
	aw.setupUI()
	return aw
}

func (aw *AppWindow) setupUI() {
	aw.Window.Resize(fyne.NewSize(800, 800))
	aw.Window.CenterOnScreen()
	aw.Window.SetContent(aw.UI.BuildUI())

	aw.UI.SSHLoginButton.OnTapped = aw.handleSSHLogin
	aw.UI.SSHEnableButton.OnTapped = aw.handleSSHEnable
	aw.UI.SSHEnablePermanentButton.OnTapped = aw.handleSSHEnablePermanent

	aw.UI.TelegramLoginBtn.OnTapped = aw.handleTelegramLogin

	aw.UI.InstallSingBoxBtn.OnTapped = aw.handleInstallSingbox
	aw.UI.InstallSingBoxPermBtn.OnTapped = aw.handleSingboxEnablePermanent
	aw.UI.UninstallSingBoxBtn.OnTapped = aw.handleUninstallSingbox

	aw.UI.ConfigFileBtn.OnTapped = aw.handleConfigSelect
	aw.UI.ConfigInstallFileBtn.OnTapped = aw.handleInstallSingboxConfig

	aw.UI.OutboundsCheckButton.OnTapped = aw.handleOutboundsCheck
	aw.UI.OutboundsApplyButton.OnTapped = aw.handleOutboundsApply

	aw.UI.StartSingBoxBtn.OnTapped = aw.handleStartSingBox
	aw.UI.StopSingBoxBtn.OnTapped = aw.handleStopSingBox
	aw.UI.RestartSingBoxBtn.OnTapped = aw.handleRestartSingBox

	aw.UI.InstallDnsBoxBtn.OnTapped = aw.handleInstallDnsBox
	aw.UI.UninstallDnsBoxBtn.OnTapped = aw.handleUninstallDnsBox
	aw.UI.InstallPermDnsBoxBtn.OnTapped = aw.handleInstallDnsBoxPermanent
	aw.UI.StartDnsBoxBtn.OnTapped = aw.handleStartDnsBox
	aw.UI.StopDnsBoxBtn.OnTapped = aw.handleStopDnsBox
	aw.UI.RestartDnsBoxBtn.OnTapped = aw.handleRestartDnsBox

	aw.UI.FirewallPatchInstallBtn.OnTapped = aw.handleFirewallPatchInstall
	aw.UI.FirewallPatchUninstallBtn.OnTapped = aw.handleFirewallPatchUninstall
	aw.UI.FirewallReloadBtn.OnTapped = aw.handleFirewallReload

	aw.UI.BypassLoadButton.OnTapped = aw.handleBypassLoad
	aw.UI.BypassCheckButton.OnTapped = aw.handleBypassCheck
	aw.UI.BypassApplyButton.OnTapped = aw.handleBypassApply

	aw.UI.DomainsLoadButton.OnTapped = aw.handleDomainsLoad
	aw.UI.DomainsCheckButton.OnTapped = aw.handleDomainsCheck
	aw.UI.DomainsApplyButton.OnTapped = aw.handleDomainsApply

	aw.UI.VLANButton.OnTapped = aw.handleVLAN
	aw.UI.UARTButton.OnTapped = aw.handleUART
	aw.UI.RebootButton.OnTapped = aw.handleReboot

	//aw.UI.CopyFilesButton.OnTapped = aw.handleCopyFiles
	go aw.Services.ScanSubnet(aw.UI.IPInput)
	aw.UI.IPInput.OnChanged = func(s string) {
		authClient := router.NewAuthClient(aw)
		var r = authClient.GetRouterInfo(aw.UI.IPInput.Text)
		if r == nil {
			aw.LogWrite("Error when get router info")
			return
		}
		if r.Inited == 0 {
			aw.LogWrite("Please setup router setup first time.")
		}
		var sshPass string
		sshPass = aw.AuthClient.CalcPasswd(r.ID)
		aw.UI.SSHPasswordInput.SetText(sshPass)

		aw.SSHClient = router.NewSSHManager(aw, aw, sshPass)

		imageData, err := embedded.GetRouterImage(r.Hardware)
		if err != nil {
			aw.LogWrite(fmt.Sprintf("Error image loading: %v", err))
			return
		}
		aw.UI.RouterImage.Resource = fyne.NewStaticResource(r.Model, imageData)
		aw.UI.RouterImage.Refresh()
		aw.UI.RouterImage.Show()
	}
}

func (aw *AppWindow) handleSSHLogin() {
	ip := aw.UI.IPInput.Text
	password := aw.UI.PasswordInput.Text

	aw.runTask(func() {
		stok, sshPass, err := aw.AuthClient.GetSSHCredentials(ip, password)
		if err != nil {
			aw.LogWrite(fmt.Sprintf("Error: %v", err))
			return
		}

		runOnMain(func() {
			aw.UI.StokInput.SetText(stok)
			aw.UI.SSHPasswordInput.SetText(sshPass)
		})
		aw.LogWrite("STOK obtained successfully!")
		aw.startRamPoller()
	})
}

// startRamPoller polls router RAM usage every 10s and updates the label on
// the device tab. It runs on its own SSH connection outside the busy lock so
// it never blocks (or is blocked by) user-triggered operations, and starts
// at most once per app run.
func (aw *AppWindow) startRamPoller() {
	if aw.SSHClient == nil {
		return
	}
	if !aw.ramPollerStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		update := func() {
			ip := aw.UI.IPInput.Text
			sshPass := aw.UI.SSHPasswordInput.Text
			if ip == "" || sshPass == "" {
				return
			}
			mem, err := aw.SSHClient.GetMemInfo(ip, sshPass)
			if err != nil {
				return
			}
			text := formatMemInfo(mem)
			runOnMain(func() {
				aw.UI.RamInfoLabel.SetText(text)
				aw.UI.RamInfoLabel.Show()
			})
		}
		update()
		for range ticker.C {
			update()
		}
	}()
}

func formatMemInfo(m *router.MemInfo) string {
	mb := func(kb uint64) float64 { return float64(kb) / 1024 }
	return fmt.Sprintf("RAM: %.0f MB\nused %.0f  free %.0f\ncached %.0f",
		mb(m.Total), mb(m.Used), mb(m.Free), mb(m.Cached))
}

func (aw *AppWindow) handleSSHEnable() {
	ip := aw.UI.IPInput.Text
	stok := aw.UI.StokInput.Text
	aw.runTask(func() {
		authClient := router.NewAuthClient(aw)
		authClient.EnableSSH(ip, stok)
	})
}

func (aw *AppWindow) handleConfigSelect() {
	dialog.ShowFileOpen(func(uri fyne.URIReadCloser, err error) {
		if err != nil || uri == nil {
			return
		}
		aw.UI.SingboxConfigInput.SetText(uri.URI().Path())
		uri.Close()
	}, aw.Window)
}

func (aw *AppWindow) handleSSHEnablePermanent() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.EnableSSHPermanent(ip, sshPass)
	})
}

// runSSHTask captures the router credentials from the UI on the main
// goroutine and runs the given SSH operation in the background.
func (aw *AppWindow) runSSHTask(task func(ip, sshPass string)) {
	if !aw.requireSSH() {
		return
	}
	ip := aw.UI.IPInput.Text
	sshPass := aw.UI.SSHPasswordInput.Text
	aw.runTask(func() {
		task(ip, sshPass)
	})
}

func (aw *AppWindow) handleTelegramLogin() {
	url := "https://t.me/vpn4test_bot?start=" + tsid.Fast().ToString()
	//exec.Command("xdg-open", url).Start()
	//
	//exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()

	exec.Command("open", url).Start()
}

func (aw *AppWindow) startLocalServer() {
	http.HandleFunc("/deeplink", func(w http.ResponseWriter, r *http.Request) {
		link := r.URL.Query().Get("url")
		fmt.Println("Получена ссылка:", link)
		aw.handleDeepLink(link)
		w.Write([]byte("OK"))
	})
	http.ListenAndServe("127.0.0.1:7777", nil)
}

// TODO fix this
func (aw *AppWindow) handleDeepLink(link string) {
	u, err := url.Parse(link)
	if err != nil {
		fmt.Println("Ошибка парсинга ссылки:", err)
		return
	}
	aw.LogWrite("Получен ключ: " + u.String())
}

func (aw *AppWindow) handleCopyFiles() {
	//aw.SSHClient.InstallSingBox(aw.UI.CopyFilesInput.Text())
}

func (aw *AppWindow) handleInstallSingbox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.InstallSingBox(ip, sshPass)
	})
}

func (aw *AppWindow) handleUninstallSingbox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.UninstallSingBox(ip, sshPass)
	})
}

func (aw *AppWindow) handleInstallSingboxConfig() {
	configPath := aw.UI.SingboxConfigInput.Text
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.InstallSingBoxConfig(ip, sshPass, configPath, false)
	})
}

func (aw *AppWindow) handleOutboundsCheck() {
	config := aw.ConfigManager
	if config.OutboundsCheck(aw.UI.OutboundsInput.Text) {
		aw.LogWrite("Check successful!")
		aw.UI.OutboundsApplyButton.Enable()
		return
	}
	aw.LogWrite("Check failed!")
	aw.UI.OutboundsApplyButton.Enable()
}

func (aw *AppWindow) handleOutboundsApply() {
	outbounds := aw.UI.OutboundsInput.Text
	aw.runSSHTask(func(ip, sshPass string) {
		fullSingBoxConfig, err := aw.SSHClient.ReadRemoteFile("/data/sing-box/config.json", ip, sshPass)
		if err != nil {
			aw.LogWrite("Error reading remote file: " + err.Error())
			return
		}
		newConfig, err := aw.ConfigManager.ApplyOutbounds(fullSingBoxConfig.Bytes(), outbounds)
		if err != nil {
			aw.LogWrite("Error applying outbounds: " + err.Error())
			return
		}
		aw.SSHClient.InstallSingBoxConfig(ip, sshPass, newConfig, true)
	})
}

func (aw *AppWindow) handleSingboxEnablePermanent() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.EnableSingboxPermanent(ip, sshPass)
	})
}

func (aw *AppWindow) handleInstallDnsBoxPermanent() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.EnableDnsBoxPermanent(ip, sshPass)
	})
}

func (aw *AppWindow) handleStartSingBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/sing-box", "start")
	})
}

func (aw *AppWindow) handleStopSingBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/sing-box", "stop")
	})
}

func (aw *AppWindow) handleRestartSingBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/sing-box", "restart")
	})
}

func (aw *AppWindow) handleInstallDnsBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		if !aw.SSHClient.InstallDnsBox(ip, sshPass) {
			return
		}
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/dnsmasq", "restart")
		aw.restoreSavedDomains(ip, sshPass)
	})
}

func (aw *AppWindow) handleUninstallDnsBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.UninstallDnsBox(ip, sshPass)
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/dnsmasq", "restart")
	})
}

func (aw *AppWindow) handleStartDnsBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/dns-box", "start")
	})
}

func (aw *AppWindow) handleStopDnsBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/dns-box", "stop")
	})
}

func (aw *AppWindow) handleRestartDnsBox() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ServiceOps(ip, sshPass, "/etc/init.d/dns-box", "restart")
	})
}

func (aw *AppWindow) handleFirewallPatchInstall() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.FirewallPatchInstall(ip, sshPass)
	})
}

func (aw *AppWindow) handleFirewallPatchUninstall() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.FirewallPatchUninstall(ip, sshPass)
	})
}

func (aw *AppWindow) handleFirewallReload() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.FirewallReload(ip, sshPass)
	})
}

func (aw *AppWindow) handleBypassLoad() {
	aw.runSSHTask(func(ip, sshPass string) {
		content, err := aw.SSHClient.GetBypassList(ip, sshPass)
		if err != nil {
			aw.LogWrite("Error loading bypass list: " + err.Error())
			return
		}
		runOnMain(func() {
			aw.UI.BypassIPsInput.SetText(content)
		})
		aw.LogWrite("Bypass list loaded from router.")
	})
}

func (aw *AppWindow) handleBypassCheck() {
	if _, err := aw.ConfigManager.NormalizeBypassList(aw.UI.BypassIPsInput.Text); err != nil {
		aw.LogWrite("Check failed: " + err.Error())
		aw.UI.BypassApplyButton.Disable()
		return
	}
	aw.LogWrite("Check successful!")
	aw.UI.BypassApplyButton.Enable()
}

func (aw *AppWindow) handleBypassApply() {
	content, err := aw.ConfigManager.NormalizeBypassList(aw.UI.BypassIPsInput.Text)
	if err != nil {
		aw.LogWrite("Check failed: " + err.Error())
		return
	}
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ApplyBypassList(ip, sshPass, content)
	})
}

func (aw *AppWindow) handleDomainsLoad() {
	aw.runSSHTask(func(ip, sshPass string) {
		// Источник истины — отдельный файл vpn_domains.txt. Пока его нет
		// (старые установки), мигрируем из конфига dns-box.
		text, err := aw.SSHClient.GetDomainList(ip, sshPass)
		if err == nil && strings.TrimSpace(text) != "" {
			runOnMain(func() {
				aw.UI.DomainsInput.SetText(text)
			})
			aw.LogWrite("Domain list loaded from router.")
			return
		}

		config, err := aw.SSHClient.GetDnsBoxConfig(ip, sshPass)
		if err != nil {
			aw.LogWrite("Error loading dns-box config: " + err.Error())
			return
		}
		cfgText, err := aw.ConfigManager.DomainsFromDnsBoxConfig(config)
		if err != nil {
			aw.LogWrite("Error parsing dns-box config: " + err.Error())
			return
		}
		runOnMain(func() {
			aw.UI.DomainsInput.SetText(cfgText)
		})
		aw.LogWrite("Domain list loaded from dns-box config (no saved list yet).")
	})
}

func (aw *AppWindow) handleDomainsCheck() {
	if _, _, err := aw.ConfigManager.ParseDomainList(aw.UI.DomainsInput.Text); err != nil {
		aw.LogWrite("Check failed: " + err.Error())
		aw.UI.DomainsApplyButton.Disable()
		return
	}
	aw.LogWrite("Check successful!")
	aw.UI.DomainsApplyButton.Enable()
}

func (aw *AppWindow) handleDomainsApply() {
	domains, suffixes, err := aw.ConfigManager.ParseDomainList(aw.UI.DomainsInput.Text)
	if err != nil {
		aw.LogWrite("Check failed: " + err.Error())
		return
	}
	domainText := services.DomainListText(domains, suffixes)
	aw.runSSHTask(func(ip, sshPass string) {
		config, err := aw.SSHClient.GetDnsBoxConfig(ip, sshPass)
		if err != nil {
			aw.LogWrite("Error loading dns-box config: " + err.Error())
			return
		}
		newConfig, err := aw.ConfigManager.ApplyDomainsToDnsBoxConfig(config, domains, suffixes)
		if err != nil {
			aw.LogWrite("Error updating dns-box config: " + err.Error())
			return
		}
		aw.SSHClient.ApplyDnsBoxConfig(ip, sshPass, newConfig, domainText)
	})
}

// restoreSavedDomains re-applies the persisted domain list into a freshly
// installed dns-box config. Reinstalling dns-box drops the embedded default
// config (without the user's domains), so we merge the saved vpn_domains.txt
// back in. No-op on a first install (the file does not exist yet).
func (aw *AppWindow) restoreSavedDomains(ip, sshPass string) {
	text, err := aw.SSHClient.GetDomainList(ip, sshPass)
	if err != nil || strings.TrimSpace(text) == "" {
		return
	}
	domains, suffixes, err := aw.ConfigManager.ParseDomainList(text)
	if err != nil {
		aw.LogWrite("Saved domain list is invalid, skipping restore: " + err.Error())
		return
	}
	config, err := aw.SSHClient.GetDnsBoxConfig(ip, sshPass)
	if err != nil {
		aw.LogWrite("Error reading dns-box config for domain restore: " + err.Error())
		return
	}
	newConfig, err := aw.ConfigManager.ApplyDomainsToDnsBoxConfig(config, domains, suffixes)
	if err != nil {
		aw.LogWrite("Error merging saved domains: " + err.Error())
		return
	}
	aw.LogWrite("Restoring saved domain list into dns-box config...")
	aw.SSHClient.ApplyDnsBoxConfig(ip, sshPass, newConfig, services.DomainListText(domains, suffixes))
}

func (aw *AppWindow) handleVLAN() {
	vlanID := aw.UI.VlanIdEntry.Text
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ConfigureVLAN(ip, sshPass, vlanID)
	})
}

func (aw *AppWindow) handleUART() {
	aw.runSSHTask(func(ip, sshPass string) {
		aw.SSHClient.ConfigureUART(ip, sshPass)
	})
}

func (aw *AppWindow) handleReboot() {
	if aw.UI.StokInput.Text == "" {
		aw.LogWrite("Please get STOK first.")
		return
	}
	ip := aw.UI.IPInput.Text
	stok := aw.UI.StokInput.Text
	aw.runTask(func() {
		authClient := router.NewAuthClient(aw)
		authClient.RebootRouter(ip, stok)
	})
}

func (aw *AppWindow) LogWriteNoNewLine(message string) {
	runOnMain(func() {
		lastContent := aw.UI.LogContent
		lastNewLineIndex := strings.LastIndex(lastContent, "\n")
		if lastNewLineIndex == -1 {
			lastNewLineIndex = 0
		} else {
			lastNewLineIndex++
		}

		lineLength := len(lastContent[lastNewLineIndex:])
		if lineLength+len(message) > 95 {
			aw.UI.LogContent += "\n" + message
		} else {
			aw.UI.LogContent += message
		}
		aw.UI.LogText.SetText(aw.UI.LogContent)
		aw.UI.LogScroll.ScrollToBottom()
	})
}

func (aw *AppWindow) LogWrite(message string) {
	runOnMain(func() {
		var splitMessage string
		if len(message) > 95 {
			splitMessage = SplitString(message)
		}
		splitMessage = message
		aw.UI.LogContent += splitMessage + "\n"
		aw.UI.LogText.SetText(aw.UI.LogContent)
		aw.UI.LogScroll.ScrollToBottom()
	})
}

func (aw *AppWindow) LogWriteWithProgress(startText string, task func() error) {
	aw.LogWriteNoNewLine(startText)

	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		dots := "."

		for {
			select {
			case <-ticker.C:
				dots += "."
				aw.LogWriteNoNewLine(dots)
			case <-done:
				return
			}
		}
	}()

	err := task()
	close(done)

	if err != nil {
		aw.LogWriteNoNewLine(fmt.Sprintf("\nError: %s.\n", err.Error()))
	} else {
		aw.LogWriteNoNewLine(" success!\n")
	}
}

func SplitString(input string) string {
	maxLen := 95
	var result string

	for i := 0; i < len(input); i += maxLen {
		end := i + maxLen
		if end > len(input) {
			end = len(input)
		}
		substr := input[i:end]
		if len(substr) > 0 && substr[len(substr)-1] != '\n' {
			substr += "\n"
		}
		result += substr
	}
	return result
}
