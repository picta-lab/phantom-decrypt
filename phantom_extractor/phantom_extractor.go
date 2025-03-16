package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"strconv"
	"github.com/btcsuite/btcutil/base58"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/table"
)

/*

GNU General Public License v2.0
https://github.com/picta-lab/phantom_decrypt/blob/main/LICENSE

version history
v0.1.0-2025-01-16;
	initial release
v0.2.0-2025-02-22-1500;
	add support for older vaults
v0.3.1-2025-02-23-1145;
	added raw db support for reading corrupt or non-standard leveldb files
v0.3.2-2025-03-01-1415;
	updated help info for Chrome extensions on Linux, Mac and Windows
v0.3.3-2025-03-07;
	added support for hashcat modes 30010, 26650, 26651
*/

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Phantom Vault Extractor v0.3.3-2025-02-04\nhttps://github.com/cyclone-github/phantom_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./phantom_extractor.bin [-version] [-help] [phantom_vault_dir]
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/

Default Phantom vault locations for Chrome extensions:

Linux:
/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/

Mac:
Library>Application Support>Google>Chrome>Default>Local Extension Settings>bfnaelmomeimhlpmgjnjophhpkkoljpa

Windows:
C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen() {
	fmt.Println(" ----------------------------------------------------- ")
	fmt.Println("|        PictaLab's Phantom Vault Extractor           |")
	fmt.Println("|        Use Phantom Vault Decryptor to decrypt       |")
	fmt.Println("|    https://github.com/picata-lab/phantom_decrypt    |")
	fmt.Println(" ----------------------------------------------------- ")
}

// struct for Phantom vaults
type EncryptedKey struct {
	Digest     string `json:"digest"`
	Encrypted  string `json:"encrypted"`
	Iterations int    `json:"iterations"`
	Kdf        string `json:"kdf"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt"`
}

// vault format "version_0"
type Vault_0 struct {
	Expiry float64 `json:"expiry"`
	Value  string  `json:"value"`
}

// vault format "version_1"
type Vault_1 struct {
	EncryptedKey EncryptedKey `json:"encryptedKey"`
	Version      int          `json:"version"`
}

// processLevelDB with version handling
func processLevelDB(i int,data []byte) {
	// detect vault version
	s2 := strconv.Itoa(i)
	str := string(data)
    //fmt.Println(str)
	

	//fmt.Fprintf("%s",data)
	version := detectVersion(data)
	//fmt.Println("in processleveldb")
	switch version {
	case 1: // vault version_1
		fmt.Println("version 1")
		var vault_1 Vault_1
		if err := json.Unmarshal(data, &vault_1); err == nil {
			printJSONVaultandSave(vault_1)
			printHashcatHash(vault_1)
		}
	case 0: // vault version_0
	fmt.Println("version 0")
		var vault_0 Vault_0
		if err := json.Unmarshal(data, &vault_0); err == nil {
			cleanStr := strings.ReplaceAll(vault_0.Value, `\`, "") // remove "\" so json can be unmarshaled
			var encryptedKey EncryptedKey
			if err := json.Unmarshal([]byte(cleanStr), &encryptedKey); err == nil {
				vault_0 := Vault_1{
					EncryptedKey: encryptedKey,
					Version:      0, // mark as version_0 to keep backwards compatibility with phantom_decryptor
				}
				printJSONVaultandSave(vault_0)
				printHashcatHash(vault_0)
			}
		}
	default:
		// do nothing
		//fmt.Println("default")
		}
	}
}

// print valid JSON vaults
func printJSONVaultandSave(entry Vault_1) {
	// sanity check if vault is valid (not empty)
	if entry.EncryptedKey.Digest != "" && entry.EncryptedKey.Encrypted != "" && entry.EncryptedKey.Iterations != 0 &&
		entry.EncryptedKey.Kdf != "" && entry.EncryptedKey.Nonce != "" && entry.EncryptedKey.Salt != "" {
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			fmt.Println("Error marshalling entry to JSON:", err)
			return
		}
		fmt.Println(string(entryJSON))
		f, err := os.Create("HASH.txt")
		if err != nil {
			 log.Fatal(err)
		}

		n, err := f.WriteString(string(entryJSON) + "\n")
		if err != nil {
			 log.Fatal(err)
		}
		fmt.Printf("enrpyted json written to HASH.txt\n", n)
		f.Sync()
	}
}

// vault version detection
func detectVersion(data []byte) int {
	if strings.Contains(string(data), "\"encryptedKey\":") {
		return 1
	} else if strings.Contains(string(data), "\"expiry\":") {
		return 0
	}
	return -1 // unknown version
}

// vault version detection
func detectOtherJson(data []byte) int {
	if strings.Contains(string(data), "\"content\":") {
		return 1
	}
	
	return 0 // unknown version
	
}

func dumpRawLDBFiles(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to access path %s: %v", path, err)
			return nil
		}
		fmt.Fprintf(os.Stderr, "in walk %s", info.Name())
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".ldb") {
			fmt.Fprintln(os.Stderr, "found walk")
			err = dumpRawLDBFile(path)
			if err != nil {
				log.Printf("Failed to dump file %s: %v", path, err)
			}
		}
		return nil
	})
}

func dumpRawLDBFile(filePath string) error {
	fmt.Fprintln(os.Stderr, "indumpraw")
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	reader, err := table.NewReader(file, fileInfo.Size(), storage.FileDesc{Type: storage.TypeTable, Num: 0}, nil, nil, &opt.Options{})
	if err != nil {
		return fmt.Errorf("failed to create table reader: %w", err)
	}
	defer reader.Release()

	iter := reader.NewIterator(nil, nil)
	defer iter.Release()
	i :=1
	for iter.Next() {
		value := iter.Value()
		processLevelDB(i,filterPrintableBytes(value))
		i +=1
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	return nil
}

func filterPrintableBytes(data []byte) []byte {
	printable := make([]rune, 0, len(data))
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			printable = append(printable, rune(b))
		} else {
			printable = append(printable, '.')
		}
	}
	return []byte(string(printable))
}

// print hashcat modes 30010, 26650, 26651
func printHashcatHash(vault Vault_1) {

	saltDecoded := base58.Decode(vault.EncryptedKey.Salt)
	nonceDecoded := base58.Decode(vault.EncryptedKey.Nonce)
	encryptedDecoded := base58.Decode(vault.EncryptedKey.Encrypted)

	saltB64 := base64.StdEncoding.EncodeToString(saltDecoded)
	nonceB64 := base64.StdEncoding.EncodeToString(nonceDecoded)
	encryptedB64 := base64.StdEncoding.EncodeToString(encryptedDecoded)

	// scrypt KDF
	if strings.ToLower(vault.EncryptedKey.Kdf) == "scrypt" {
		fmt.Println(" ----------------------------------------------------- ")
		fmt.Println("|          hashcat -m 26650 hash (scrypt kdf)         |")
		fmt.Println(" ----------------------------------------------------- ")
		// PHANTOM:4096:8:1:<salt_b64>:<nonce_b64>:<encrypted_b64>
		fmt.Printf("PHANTOM:4096:8:1:%s:%s:%s\n", saltB64, nonceB64, encryptedB64)
		return
	}

	// pbkdf2 KDF
	if strings.ToLower(vault.EncryptedKey.Kdf) == "pbkdf2" {
		fmt.Println(" ----------------------------------------------------- ")
		fmt.Println("|          hashcat -m 30010 hash (pbkdf2 kdf)         |")
		fmt.Println(" ----------------------------------------------------- ")
		// $phantom$<salt_b64>$<nonce_b64>$<encrypted_b64>
		fmt.Printf("$phantom$%s$%s$%s\n", saltB64, nonceB64, encryptedB64)

		fmt.Println(" ----------------------------------------------------- ")
		fmt.Println("|          hashcat -m 26651 hash (pbkdf2 kdf)         |")
		fmt.Println(" ----------------------------------------------------- ")
		// PHANTOM:10000:<salt_b64>:<nonce_b64>:<encrypted_b64>
		fmt.Printf("PHANTOM:10000:%s:%s:%s\n", saltB64, nonceB64, encryptedB64)
	}
}

// main
func main() {
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	ldbDir := flag.Arg(0)
	if ldbDir == "" {
		fmt.Fprintln(os.Stderr, "Error: Phantom vault directory is required")
		helpFunc()
		os.Exit(1)
	}

	printWelcomeScreen()
	fmt.Println("After welcome screen")
	db, err := leveldb.OpenFile(ldbDir, nil)
	fmt.Println("check1")
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, "Error opening Vault:", err)
		fmt.Println("Attempting to dump raw .ldb files...")
		err = dumpRawLDBFiles(ldbDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to dump raw .ldb files: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	//}
	defer db.Close()
	fmt.Println("check2")

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	fmt.Println("check3")
	for iter.Next() {
		fmt.Println("check4")
		value := iter.Value()
		processLevelDB(0,value)
	}
}

// end code
