package main

import (
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	rdapp "github.com/romanychev/be3600/internal/app"
)

func main() {
	myApp := app.NewWithID("io.be3600.tool")
	myApp.Settings().SetTheme(LoadPlatformTheme())
	rdapp.NewAppWindow(myApp).Window.ShowAndRun()
}

func LoadPlatformTheme() fyne.Theme {
	switch runtime.GOOS {
	case "darwin":
		return &rdapp.MacTheme{}
	case "windows":
		return &rdapp.WindowsTheme{}
	default:
		return &rdapp.MobileTheme{}
	}
}
