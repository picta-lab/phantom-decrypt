
# 🚀 Phantom Vault Extractor & Decryptor
The Phantom Vault Extactor and decryptor is the first tool to recover, extract and decrypt Phantom wallet Vaults
## ✨ Features
- extract encrypted key
- decrypt encrypted main key
- use main key to decrypt other crypted json
- Contact me at https://t.me/pictalab if you need help recovering your Phantom wallet password or seed phrase.


### Phantom vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/`
- Mac: `Library>Application Support>Google>Chrome>Default>Local Extension Settings>bfnaelmomeimhlpmgjnjophhpkkoljpa`
- Windows: `C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\`
### Extractor usage example on test vault: (plaintext is `password`)
* Old pbkdf2 KDF
```
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/
 ----------------------------------------------------- 
|       Picta Lab's Phantom Vault Hash Extractor      |
|        Use Phantom Vault Decryptor to decrypt       |
|    https://github.com/picta-lab/phantom-decrypt     |
 ----------------------------------------------------- 
{"encryptedKey":{"digest":"sha256","encrypted":"5pLvA3bCjNGYBbSjjFY3mdPknwFfp3cz9dCBv6izyyrqEhYCBkKwo3zZUzBP44KtY3","iterations":10000,"kdf":"pbkdf2","nonce":"NZT6kw5Cd5VeZu5yJGJcFcP24tnmg4xsR","salt":"A43vTZnm9c5CiQ6FLTdV9v"},"version":1}
 ----------------------------------------------------- 
|          hashcat -m 30010 hash (pbkdf2 kdf)         |
 ----------------------------------------------------- 
$phantom$SU9HoVMjb1ieOEv18nz3FQ==$7H29InVRWVbHS4WcBJdTay0ONb4mLX9Q$g0vJAbflhH4jJJDvuv7Ar5THgzBmJ8tt6oajsQZd/dSXNNjcY5/0eGeF5c1NW1WU
 ----------------------------------------------------- 
|          hashcat -m 26651 hash (pbkdf2 kdf)         |
 ----------------------------------------------------- 
PHANTOM:10000:SU9HoVMjb1ieOEv18nz3FQ==:7H29InVRWVbHS4WcBJdTay0ONb4mLX9Q:g0vJAbflhH4jJJDvuv7Ar5THgzBmJ8tt6oajsQZd/dSXNNjcY5/0eGeF5c1NW1WU
```
* New scrypt KDF
```
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/
 ----------------------------------------------------- 
|        Picata-lab's Phantom Vault Hash Extractor    |
|        Use Phantom Vault Decryptor to decrypt       |
|    https://github.com/picta-lab/phantom-decrypt     |
 ----------------------------------------------------- 
{"encryptedKey":{"digest":"sha256","encrypted":"37fJoKsB9vwnKEzPgc2AHtYVsPTTzrXdTGacbgWxLxbiS7Ri3P3iNnf8csaKwJ4wpk","iterations":10000,"kdf":"scrypt","nonce":"49aomus4HiKLyg7F66pSinR4tpuUuJDHX","salt":"M1PMFn4p4gdCxZDzf8qX71"},"version":1}
 ----------------------------------------------------- 
|          hashcat -m 26650 hash (scrypt kdf)         |
 ----------------------------------------------------- 
PHANTOM:4096:8:1:ogSL4J4xP/wNbAjiA8Q4hA==:Iofs3VYyyaYFzHVkcMsnpkrjGQ2+Kni2:OacHaTJAM8dD7XJIj5bGMU3cM8QW3u92n+ngYjXsgRSR20FDnkMLQHTgPxJDefOx

```
### Decryptor usage example:
```
 ----------------------------------------------- 
|       Picta-lab Phantom Vault Decryptor       |
| https://github.com/picta-lab/phantom-decrypt  |
 ----------------------------------------------- 

Vault file:     hash.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
2024/11/30 14:11:35 Working...
{"encryptedKey":{"digest":"sha256","encrypted":"5pLvA3bCjNGYBbSjjFY3mdPknwFfp3cz9dCBv6izyyrqEhYCBkKwo3zZUzBP44KtY3","iterations":10000,"kdf":"pbkdf2","nonce":"NZT6kw5Cd5VeZu5yJGJcFcP24tnmg4xsR","salt":"A43vTZnm9c5CiQ6FLTdV9v"},"version":1}:password
2024/11/30 14:11:39 Decrypted: 1/1 6181.36 h/s 00h:00m:03s

2024/11/30 14:11:39 Finished

```
### Decryptor supported options:
```
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

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o output.txt
```

## 🛠 Installation

### Compile from source:
- This assumes you have Go and Git installed
  - `git clone https://github.com/picta-lab/phantom-decrypt.git`
  - phantom_extractor
  - `cd phantom-decrypt/phantom_extractor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" .`
  - phantom_decryptor
  - `cd phantom-decrypt/phantom_decryptor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" .`
- Compile from source code how-to:
  - https://github.com/picta-lab/scripts/blob/main/intro_to_go.txt
