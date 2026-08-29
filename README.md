# Bastion

**Bastion** is a high-security, zero-dependency toolbox compiled into a single binary. It provides a suite of cryptographic tools ranging from AES-256-GCM file encryption and cryptographic shredding to live TOTP authentication and secret scanning.

It features a rich Terminal User Interface (TUI) for interactive use, while remaining fully scriptable and pipeable for headless operations.

## Features

- **Zero Dependencies**: Built entirely using the Go 1.22+ standard library.
- **Single File**: All production logic lives in `bastion.go`.
- **Interactive TUI Dashboard**: Run without arguments to launch a stunning visual menu with clipboard integration, live TOTP clocks, and form-style prompts.
- **Cross-Platform**: Works seamlessly on Windows, macOS, and Linux.

## Core Capabilities

### Vault & File Operations

- **Encrypt / Decrypt**: Secure files using AES-256-GCM and PBKDF2-SHA-256. Automatically handles iterations and nonces. Includes `-rm` / `--wipe` flags to securely shred the plaintext after encryption.
  ```bash
  bastion enc secret.txt
  bastion dec secret.txt.enc
  ```
- **In-Place Edit**: Securely edit an encrypted file without leaving plaintext traces on disk. Decrypts to a secure temporary file, opens your system `$EDITOR`, re-encrypts, and cryptographically wipes the temp file on exit.
  ```bash
  bastion edit secret.txt.enc
  ```
- **View**: Decrypt a file directly to `stdout` in-memory.
  ```bash
  bastion view secret.txt.enc
  ```
- **Wipe**: A cryptographic shredder that overwrites files with random data before unlinking them, ensuring they cannot be recovered.
  ```bash
  bastion wipe sensitive.pdf
  ```

### Credentials & Auditing

- **TOTP Authenticator**: Generate and verify RFC 6238 Time-Based One-Time Passwords. Interactive mode features a live-ticking visual clock.
  ```bash
  bastion totp gen <base32-secret>
  bastion totp verify -secret <base32-secret> -code 123456
  ```
- **Password Generator**: Generate highly secure, zero-bias passwords using a CSPRNG. Automatically copies to your clipboard.
  ```bash
  bastion gen -len 32 -symbols -copy
  ```
- **Secret Scanner**: Recursively scan directories for leaked secrets based on Shannon entropy and known pattern matching.
  ```bash
  bastion scan ./project
  ```
- **File Hashing**: Stream-hash large files efficiently using SHA-256 or SHA-512.
  ```bash
  bastion hash large-archive.zip -algo sha512
  ```

## Security Guarantees

1. **Authentication First**: Decryption uses authenticated encryption (GCM). Any tampering (bit flips, truncation, chunk swaps) will result in a hard failure without leaking partial plaintext.
2. **Memory Safety**: Passwords and sensitive memory buffers are explicitly zeroed out (`defer zero(pass)`) when no longer needed.
3. **No Terminal Echo**: Cross-platform password masking (via `stty` on POSIX and PowerShell on Windows) ensures passwords never leak to the console.
4. **Secure Defaults**: Generates passwords and nonces using `crypto/rand` (CSPRNG). Evaluates entropy rigorously for secret scanning.

## Installation

Since Bastion is a single file with zero dependencies, installation is trivial:

```bash
go build -trimpath -ldflags="-s -w" -o bastion bastion.go
```

Then move `bastion` (or `bastion.exe`) to your `$PATH`.

## Usage

Run `bastion` to launch the interactive TUI Dashboard, or use it via the CLI:

```text
Usage: bastion <command> [options]

Commands:
  bastion enc  <file> [-out <path>] [-rm]                    encrypt a file
  bastion dec  <file> [-out <path>]                          decrypt a file
  bastion view <file.enc>                                    decrypt to stdout
  bastion edit <file.enc>                                    edit an encrypted file in-place
  bastion wipe <file>                                        cryptographically shred a file
  bastion totp gen <secret> [-live]                          generate a 6-digit TOTP code
  bastion totp verify -secret <secret> -code <digits>        verify a TOTP code
  bastion scan [<dir>] [-dir <path>] [-entropy <float>]      hunt for leaked secrets (default: .)
  bastion gen  [-len <int>] [-symbols] [-copy]               generate a strong password
  bastion hash [<file>] [-file <path>] [-algo sha256|sha512] stream-hash a file

EXIT CODES
  0  success        1  bad arguments or I/O error        2  tamper / secret found
```
