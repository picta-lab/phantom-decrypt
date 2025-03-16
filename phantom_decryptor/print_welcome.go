package main

import (
	"fmt"
	"log"
	"os"
)

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Phantom Vault Decryptor v0.1.5-2024-11-30-1415\nhttps://github.com/cyclone-github/phantom_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {phantom_wallet_hash}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)

./phantom_decryptor.bin -h {phantom_wallet_hash} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./phantom_decryptor.bin -h phantom.txt

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o output.txt`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|       Cyclone's Phantom Vault Decryptor       |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/phantom_pwn |")
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)

	// assume "stdin" if wordlistFileFlag is ""
	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	//fmt.Fprintln(os.Stderr, "Working...")
	log.Println("Working...")
}
