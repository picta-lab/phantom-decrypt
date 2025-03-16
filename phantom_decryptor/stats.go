package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// monitor status
func monitorPrintStats(crackedCount *int32, linesProcessed *int32, stopChan <-chan struct{}, startTime time.Time, validVaultCount int, wg *sync.WaitGroup, interval int) {

	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
	}

	for {
		select {
		case <-stopChan:
			// print final stats and exit
			printStats(time.Since(startTime), int(atomic.LoadInt32(crackedCount)), validVaultCount, int(atomic.LoadInt32(linesProcessed)), true)
			wg.Done()
			return
		case <-func() <-chan time.Time {
			if ticker != nil {
				return ticker.C
			}
			return nil
		}():
			if interval > 0 {
				printStats(time.Since(startTime), int(atomic.LoadInt32(crackedCount)), validVaultCount, int(atomic.LoadInt32(linesProcessed)), false)
			}
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount int, validVaultCount, linesProcessed int, exitProgram bool) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	log.Printf("Decrypted: %d/%d %.2f h/s %02dh:%02dm:%02ds", crackedCount, validVaultCount, linesPerSecond, hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		time.Sleep(100 * time.Millisecond)
		os.Exit(0) // exit only if indicated by 'exitProgram' flag
	}
}
