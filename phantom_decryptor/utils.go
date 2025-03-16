package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
)

// clear screen function
func clearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		return // no action on unsupported platforms
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to clear screen:", err)
	}
}

func closeStopChannel(stopChan chan struct{}) {
	select {
	case <-stopChan:
		// channel already closed, do nothing
	default:
		close(stopChan)
	}
}

// goroutine to watch for ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		closeStopChannel(stopChan)
	}()
}

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// check if all vaults are cracked
func isAllVaultsCracked(vaults []Vault) bool {
	for i := range vaults {
		if atomic.LoadInt32(&vaults[i].Decrypted) == 0 {
			return false
		}
	}
	return true
}
