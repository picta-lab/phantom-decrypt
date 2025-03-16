package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

/*
Picta Lab Phantom Vault Decryptor


https://github.com/picta-lab/phantom-decrypt

POC tool to decrypt Phantom Vault wallets
This tool is proudly the first Phantom Vault Decryptor / Cracker
coded by picta-lab in Go


GNU General Public License v2.0
https://github.com/picta-lab/phantom-decrypt/blob/master/LICENSE

version history
v0.1.0-2025-01-20-2000; initial release
v0.1.1-2025-01-22-1600;
	refactor code
	fixed https://github.com/picta-lab/phantom-decrypt/issues/1
v0.1.2-2025-01-31-1700;
	acknowledged https://github.com/picta-lab/phantom-decrypt/issues/3
	added placeholder for scrypt KDF
v0.1.3-2025-07-02-1100;
	added support for scrypt KDF
	fixed https://github.com/picta-lab/phantom-decrypt/issues/3
v0.1.4-2025-02-15-1630;
	finished implementing flag -o {output file}
v0.1.5-2025-03-01-1415;
	fix https://github.com/picta-lab/phantom-decrypt/issues/6
	swapped crackedCount and lineProcessed channels for atomic int32 for better performance
	multiple performance optimizations in process.go
	print vault:password when vault is cracked
*/

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Vault File")
	outputFile := flag.String("o", "", "Output file to write hashes to (omit -o to print to console)")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}

	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (vault file) flags is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// variables
	var (
		crackedCount   int32
		linesProcessed int32
		wg             sync.WaitGroup
	)

	// channels
	stopChan := make(chan struct{})

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := readVaultData(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(&crackedCount, &linesProcessed, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	// start the processing logic
	startProc(*wordlistFileFlag, *outputFile, numThreads, vaults, &crackedCount, &linesProcessed, stopChan)

	// close stop channel to signal all workers to stop
	closeStopChannel(stopChan)

	// wait for monitorPrintStats to finish   
	wg.Wait()
}

// end code
