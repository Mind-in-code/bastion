# Bastion

**Bastion** is a high-security, zero-dependency security toolbox compiled into a single binary. It provides authenticated file encryption, cryptographic shredding, live TOTP 2FA, secret scanning, password generation, and file hashing — all from one self-contained executable built with Go's standard library only.

## Features

- **Zero Dependencies**: Built exclusively on the Go 1.22+ standard library. Empty `require` in `go.mod`.
- **Single File**: All production logic lives in `bastion.go`. No vendored code.
- **Interactive TUI Dashboard**: Run without arguments for a rich, visual menu with live TOTP clocks, clipboard integration, and form prompts.
- **Cross-Platform**: Windows, macOS, and Linux. `CGO_ENABLED=0`.
- **Reproducible Builds**: Byte-identical binaries across machines (see below).
- **Cryptographic KAT Suite**: `bastion doctor` runs six Known-Answer Tests to confirm primitives are functioning correctly before any operational use.

---

## Installation

```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o bastion bastion.go
```

Move `bastion` (or `bastion.exe`) to your `$PATH`.

---

## Usage

```
Usage: bastion <command> [options]

  bastion                                                    interactive TUI menu (requires a TTY)
  bastion enc  [<file>] [-in <f>] [-out <f>] [-pass <p>] [-rounds <n>] [-rm]
                                                             encrypt (auto-names to <file>.enc)
  bastion dec  [<file>] [-in <f>] [-out <f>] [-pass <p>]   decrypt (auto-strips .enc suffix)
  bastion view <file.enc>                                    decrypt to stdout
  bastion edit <file.enc>                                    securely edit in place
  bastion wipe <file>                                        cryptographic file shredder
  bastion totp gen    [<secret>] [-secret <b32>]            generate a 6-digit TOTP code
  bastion totp verify [<secret>] [<code>] [-secret] [-code] verify a code (±1 step drift)
  bastion scan [<dir>] [-dir <path>] [-entropy <float>]     hunt for leaked secrets (default: .)
  bastion gen  [-len <int>] [-symbols] [-copy]              generate a strong password
  bastion hash [<file>] [-file <path>] [-algo sha256|sha512] stream-hash a file
  bastion doctor                                             run cryptographic self-diagnostics (KAT)
  bastion bench                                             run live hardware performance benchmarks

EXIT CODES
  0  success        1  bad arguments or I/O error        2  tamper / secret found
```

> **Tip:** Flags may appear before or after positional arguments, e.g. both `bastion hash file.txt -algo sha512` and `bastion hash -algo sha512 file.txt` work identically.

---

## Commands

### Vault & File Operations

| Command | Description |
|---|---|
| `bastion enc secret.txt` | Encrypt to `secret.txt.enc` with PBKDF2 + AES-256-GCM. Prompts for password. |
| `bastion enc secret.txt -pass pw -rm` | Encrypt and auto-wipe plaintext source. |
| `bastion dec secret.txt.enc` | Decrypt; auto-strips `.enc` to produce `secret.txt`. |
| `bastion view secret.txt.enc` | Decrypt in-memory to stdout, no disk writes. |
| `bastion edit secret.txt.enc` | Decrypt to secure temp file, open `$EDITOR`, re-encrypt, wipe temp. |
| `bastion wipe oldfile.pdf` | Cryptographic shredder: random bytes + zero overwrite + unlink. |

### Credentials & Auditing

| Command | Description |
|---|---|
| `bastion totp gen JBSWY3DPEHPK3PXP` | Live-ticking TOTP clock with progress bar in TTY, raw 6-digit code when piped. |
| `bastion totp verify -secret JBSWY3DPEHPK3PXP -code 123456` | Validates code with ±1 step drift tolerance. |
| `bastion scan ./myproject` | Scans for AWS keys, GitHub tokens, PEM blocks, high-entropy strings. Exit 2 if found. |
| `bastion gen -len 32 -symbols -copy` | CSPRNG password with auto-clipboard copy. |
| `bastion hash archive.tar.gz -algo sha512` | SHA-512 stream-hash; outputs digest to stdout (pipeable). |

### Diagnostics

| Command | Description |
|---|---|
| `bastion doctor` | Runs 6 Known-Answer Tests: PBKDF2 (RFC 7914), AES-256-GCM (NIST SP 800-38D), TOTP (RFC 6238), tamper detection, memory hygiene, CSPRNG liveness. |
| `bastion bench` | Live hardware benchmark: AES-256-GCM enc/dec throughput, TOTP/password ops/sec, SHA-256 MB/s, Shannon entropy ns/op. |

---

## Security Guarantees

### Threat Model

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM — 256-bit key derived via PBKDF2-HMAC-SHA256 (100,000 rounds default). |
| **Integrity** | Every 64 KiB chunk carries a 16-byte GCM authentication tag. Truncation, reordering, and bit-flipping all cause hard authentication failure. |
| **Nonce Reuse** | Per-chunk nonce = base XOR (counter[8] \|\| finalFlag[1]). A fresh random base nonce is generated for every encrypt operation via `crypto/rand`. |
| **Key Derivation** | PBKDF2-HMAC-SHA256 with configurable iteration count (1,000–10,000,000). Count stored in the file header; decryption never needs to be told. |
| **Side-Channels** | TOTP verification uses `crypto/subtle.ConstantTimeCompare`. Password confirmation is timing-constant. |
| **Memory Hygiene** | All key material and password buffers are explicitly zeroed (`defer zero(pass)`) immediately after use. |

### Wire Format

```
┌─────────────┬────────────────┬──────────────┬──────────────────────────────┐
│  16B Salt   │  4B Rounds     │  12B Nonce   │  64KB chunks + 16B GCM tags  │
│  (random)   │  (big-endian   │  (random     │  …repeating until EOF…       │
│             │   uint32)      │   base)      │                              │
└─────────────┴────────────────┴──────────────┴──────────────────────────────┘
```

---

## Reproducible Builds

Bastion's build is fully reproducible: two independent builds from the same source produce byte-identical binaries.

**Build command:**
```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o bastion bastion.go
```

**Verification (SHA-256):**
```
931d1c77e8fc8cd2f03103773e89d36a9fba89431f7fe62d1c9d12aa4376290c
```

To verify:
```bash
# Linux/macOS
sha256sum bastion
# Windows PowerShell
(Get-FileHash bastion.exe -Algorithm SHA256).Hash.ToLower()
```

---

## Honest Limitations

- **PBKDF2 vs Argon2id**: Bastion uses PBKDF2-HMAC-SHA256. Argon2id is preferred for new designs because it is memory-hard and resists GPU/ASIC attacks more aggressively. PBKDF2 is used here because it is available in Go's standard library without external dependencies.

- **`-pass` flag visibility**: When `-pass` is supplied on the command line, the passphrase appears in the process table and shell history. For non-interactive automation, prefer piping the password via stdin (echo `pw | bastion enc file`) or injecting it via an environment variable read by the caller.

- **Scanner entropy false positives**: The secret scanner uses Shannon entropy heuristics alongside regex patterns. High-entropy tokens like base64-encoded UUIDs, lorem ipsum encoded strings, or certain identifiers may trigger false positives. Tune the threshold with `-entropy` (default 4.5 bits/char).

- **Filesystem-level attacks**: Bastion encrypts file contents; it does not protect filenames, metadata, directory structure, or file modification times. An adversary with filesystem access can enumerate file names and sizes.

---

## Test Coverage

```bash
go test -v -cover -short .
```

- **150 tests** across 12 test groups at ~64.2% statement coverage
- 100% pass rate
- Adversarial coverage: 13 tamper/truncation/chunk-swap/splice attack simulations
- All 6 RFC 6238 TOTP reference vectors
- NIST SP 800-38D AES-256-GCM vectors
- RFC 7914 PBKDF2 vectors
- Native fuzz target: `FuzzDecryptStream` (proves panic-free invariant on arbitrary input)
- 8 micro-benchmarks including PBKDF2 key derivation throughput