package main

import (
	"bytes"
	"encoding/hex"
)

// dehex wordlist line
/* note:
the checkForHexBytes() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
if you have suggestions on how to better handle HEX decoding errors, contact me on github
*/
func checkForHexBytes(line []byte) ([]byte, []byte, int) {
	hexPrefix := []byte("$HEX[")
	suffix := byte(']')

	// Step 1: Check for prefix and adjust for missing ']'
	if bytes.HasPrefix(line, hexPrefix) {
		var hexErrorDetected int
		if line[len(line)-1] != suffix {
			line = append(line, suffix) // Correcting the malformed $HEX[]
			hexErrorDetected = 1
		}

		// Step 2: Find the indices for the content inside the brackets
		startIdx := bytes.IndexByte(line, '[')
		endIdx := bytes.LastIndexByte(line, ']')
		if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
			return line, line, 1 // Early return on malformed bracket positioning
		}
		hexContent := line[startIdx+1 : endIdx]

		// Step 3 & 4: Decode the hex content and handle errors by cleaning if necessary
		decodedBytes := make([]byte, hex.DecodedLen(len(hexContent)))
		n, err := hex.Decode(decodedBytes, hexContent)
		if err != nil {
			// Clean the hex content: remove invalid characters and ensure even length
			cleaned := make([]byte, 0, len(hexContent))
			for _, b := range hexContent {
				if ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F') {
					cleaned = append(cleaned, b)
				}
			}
			if len(cleaned)%2 != 0 {
				cleaned = append([]byte{'0'}, cleaned...) // Ensuring even number of characters
			}

			decodedBytes = make([]byte, hex.DecodedLen(len(cleaned)))
			_, err = hex.Decode(decodedBytes, cleaned)
			if err != nil {
				return line, line, 1 // Return original if still failing
			}
			hexErrorDetected = 1
		}
		decodedBytes = decodedBytes[:n] // Trim the slice to the actual decoded length
		return decodedBytes, hexContent, hexErrorDetected
	}
	// Step 5: Return original if not a hex string
	return line, line, 0
}
