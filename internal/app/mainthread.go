package app

import (
	"runtime"

	"fyne.io/fyne/v2"
)

// mainGoroutineID is captured during package init, which Go always runs on
// the main goroutine — the same goroutine Fyne's event loop lives on.
var mainGoroutineID = goroutineID()

// runOnMain executes fn on the Fyne main goroutine. Since Fyne 2.6 UI calls
// from other goroutines must go through fyne.Do, while calling fyne.Do from
// the main goroutine itself is an error, so callers that run in both contexts
// (e.g. log writers) need this dispatch.
func runOnMain(fn func()) {
	if goroutineID() == mainGoroutineID {
		fn()
		return
	}
	fyne.Do(fn)
}

func goroutineID() (id uint64) {
	var buf [30]byte
	runtime.Stack(buf[:], false)
	// The stack header is "goroutine <id> [...":  parse digits after column 10.
	for i := 10; buf[i] != ' '; i++ {
		id = id*10 + uint64(buf[i]&15)
	}
	return id
}
