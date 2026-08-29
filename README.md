# Bastion

### Zero-Dependency Security & Cryptographic Swiss Army Knife

A single-file, zero-dependency, streaming security engine in Go 1.22+.

Authenticated file encryption, TOTP two-factor codes, secret scanning, password generation and
file hashing — in one binary, built from the Go standard library and nothing else.

```
go.mod has no require block.
$ go list -m all
bastion
```

| | |
|---|---|
| **Dependencies** | 0 |
| **Production files** | 1 (`bastion.go`, 908 lines) |
| **Tests** | 96, at 90.9% statement coverage |
| **Encryption throughput** | 3,359 MB/s |
| **Memory** | O(1) — a 300 MB file peaks at 5.6 MB RSS |
| **Build** | Reproducible, byte-identical across directories |

---

## Why

Most tools in this space are assembled from a dozen third-party packages. For a *security* tool
that is a poor trade: an attacker who compromises one transitive dependency of an encryption
utility owns the encryption utility.

Bastion imports only the Go standard library — audited, versioned with the toolchain, and
hardware-accelerated. See **[STDLIB.md](STDLIB.md)** for the full audit of the eleven dependencies
that were replaced, and an honest account of what that cost.

---

## Quickstart

```bash
git clone https://github.com/Mind-in-code/bastion.git
cd bastion
make build
```

```bash
# Encrypt a file. Omit -pass and it prompts with the echo turned off.
./bastion enc -in secrets.txt -out secrets.enc

# Decrypt it back.
./bastion dec -in secrets.enc -out secrets.txt

# A 6-digit two-factor code.
./bastion totp gen -secret JBSWY3DPEHPK3PXP

# Hunt for credentials committed by accident.
./bastion scan -dir ./src

# A strong password, straight to the clipboard.
./bastion gen -len 32 -symbols | pbcopy
```

---

## Command reference

### `enc` — encrypt a file

```bash
bastion enc -in <file> -out <file> [-pass <pass>] [-rounds <n>]
```

| Flag | Default | Meaning |
|---|---|---|
| `-in` | required | Input file |
| `-out` | required | Output file |
| `-pass` | *prompt* | Passphrase. Omit it and you are prompted on stdin with echo off. |
| `-rounds` | `100000` | PBKDF2 iterations, 1,000–10,000,000. Stored in the file. |

```bash
$ ./bastion enc -in report.pdf -out report.enc
Password:
Confirm password:
✔ Encrypted report.pdf → report.enc (2481308 bytes, 100000 PBKDF2 rounds)

# OWASP 2023 guidance for PBKDF2-HMAC-SHA256 is 600,000 iterations.
$ ./bastion enc -in report.pdf -out report.enc -pass "…" -rounds 600000
✔ Encrypted report.pdf → report.enc (2481308 bytes, 600000 PBKDF2 rounds)
```

### `dec` — decrypt a file

```bash
bastion dec -in <file> -out <file> [-pass <pass>]
```

There is deliberately **no `-rounds` flag on `dec`**. The iteration count travels inside the
file, so decryption reads it and cannot be told the wrong number.

```bash
$ ./bastion dec -in report.enc -out report.pdf -pass "…"
✔ Decrypted report.enc → report.pdf (2481308 bytes)

# Any tampering, wrong password, truncation or reordering:
$ ./bastion dec -in tampered.enc -out out.pdf -pass "…"
✘ authentication failed: wrong password or the file has been tampered with
$ echo $?
2
```

No partial output file is left behind on failure.

### `totp` — RFC 6238 two-factor codes

```bash
bastion totp gen    -secret <base32>
bastion totp verify -secret <base32> -code <code>
```

```bash
$ ./bastion totp gen -secret JBSWY3DPEHPK3PXP
282760
— valid for 17s

$ ./bastion totp verify -secret JBSWY3DPEHPK3PXP -code 282760
✔ VALID code (within ±1 time step)
```

The secret is normalised for case, spaces, hyphens and missing padding, so you can paste it in
whatever shape your provider displayed it. Verification allows ±1 step (30 s) of clock drift and
compares in constant time.

### `scan` — find leaked secrets

```bash
bastion scan -dir <path> [-entropy <float>]
```

| Flag | Default | Meaning |
|---|---|---|
| `-dir` | `.` | Directory to walk recursively |
| `-entropy` | `4.5` | Shannon entropy threshold, in bits per character |

```bash
$ ./bastion scan -dir ./src
LEAK src/config.py:2  AWS Access Key ID          AKIA******MPLE
LEAK src/config.py:5  GitHub Token               ghp_******0000
LEAK src/id_rsa:1     Private Key Block          ----******----
HIGH src/session.js:1 High entropy 5.09 bits/char aZ9k******hJcV
— scanned 214 files in ./src
✘ 4 potential secret(s) found
```

Findings are **redacted** — the scanner never prints a full secret into your terminal history.
`node_modules`, `.git`, `vendor`, binaries and media files are skipped. Nine vendor patterns are
detected (AWS key ID and secret, GitHub classic and fine-grained, Slack token and webhook, Google
API key, PEM private key, bearer token); anything else with high randomness is flagged by entropy.

Raising `-entropy` reduces false positives from base64 blobs and minified code.

### `gen` — generate a password

```bash
bastion gen [-len <int>] [-symbols]
```

```bash
$ ./bastion gen -len 32 -symbols
?p,I$KagBklNphJ.2?PWKd,USTh:]?3V
— 32 chars, ~206 bits of entropy
```

Every character is drawn from `crypto/rand` with rejection sampling, so there is no modulo bias.
At least one character from each requested class is guaranteed. Minimum length 8.

### `hash` — fingerprint a file

```bash
bastion hash -file <file> [-algo sha256|sha512]
```

```bash
$ ./bastion hash -file report.pdf
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  report.pdf
```

Streamed, so file size does not affect memory.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Bad arguments, or an I/O error |
| `2` | **Security event** — tampering, wrong password, or a secret was found |

Code `2` is reserved strictly for security outcomes. A flag typo returns `1`, so a CI pipeline
watching for `2` never gets a false alarm.

---

## Threat model

### Confidentiality

**AES-256-GCM**, an AEAD construction. The key is 256 bits, derived from your passphrase; it is
never stored, and no key material touches the output file.

### Integrity and authenticity

Every 64 KiB chunk carries a **128-bit GCM authentication tag**. Decryption is **fail-closed**: on
any authentication failure it stops, returns exit code `2`, and **deletes the partial output
file** rather than handing back plausible-looking garbage.

The following are all detected and rejected:

| Attack | Why it fails |
|---|---|
| Wrong passphrase | Derives a different key; the tag does not verify |
| Single bit flip anywhere | GCM tag mismatch |
| Truncating the file | The last chunk carries a final-chunk flag in its nonce |
| Reordering chunks | Each nonce embeds the chunk's sequence number |
| Splicing in a foreign chunk | Different file, different base nonce |
| Replaying one of the file's own chunks | Sequence number no longer matches its slot |
| Editing the stored iteration count | Different count derives a different key |

Each of these is an automated test in [`bastion_test.go`](bastion_test.go).

### Key derivation

**PBKDF2-HMAC-SHA256** (RFC 2898) with a fresh **16-byte CSPRNG salt** per file. The default is
100,000 iterations; `-rounds` accepts anything from 1,000 to 10,000,000, so OWASP's 600,000
recommendation is a flag away.

The iteration count is **stored in the file**, which makes files self-describing — decryption
never needs to be told, and a count you chose years ago can never be forgotten. The 1,000–10,000,000
clamp is enforced on read: a hostile header cannot turn decryption into a CPU denial of service.
A count that has merely been *altered* needs no special handling, because it derives a different
key and fails authentication like any other tampering.

### Wire format

```
┌────────────────┬──────────────┬────────────────┬─────────────────────────────┐
│  16-byte salt  │ 4-byte rounds│ 12-byte nonce  │  chunk 0, chunk 1, chunk 2… │
│                │  (uint32 BE) │                │                             │
└────────────────┴──────────────┴────────────────┴─────────────────────────────┘
        └──────────── 32-byte header ────────────┘

each chunk:  [ up to 64 KiB ciphertext ][ 16-byte GCM tag ]
```

Total overhead: 32 bytes, plus 16 bytes per 64 KiB chunk — about 0.025%.

### Nonce freshness

The stored nonce is 96 bits from the system CSPRNG, fresh per file. Each chunk then derives its
own nonce:

```
nonce(i) = base XOR ( 0x000000 ‖ uint64BE(i) ‖ finalFlag )
```

The sequence number `i` guarantees no nonce is reused within a file — the failure mode that breaks
GCM catastrophically — and makes reordering detectable. The final-chunk flag makes truncation
detectable. The mapping is injective, so distinct `(i, final)` pairs always give distinct nonces.

### Side-channel defence

`crypto/subtle.ConstantTimeCompare` is used for TOTP verification and passphrase confirmation, so
comparison time never leaks how many bytes matched. TOTP verification checks all three time steps
with no early exit.

### Memory hygiene

Derived keys, passphrase buffers, plaintext buffers and PBKDF2 scratch space are explicitly
overwritten with zeros as soon as they are finished with. A test asserts that the passphrase
buffer is all-zero after `runCrypt` returns.

### Honest limitations

These are real, and we would rather state them than have you discover them:

1. **`-pass` on the command line is visible.** It lands in your shell history and in the process
   table, where other users on the machine can read it with `ps`. **Omit `-pass` and use the
   prompt** for anything that matters.

2. **Passphrase zeroing is incomplete when `-pass` is used.** Go's `flag` package produces an
   immutable `string`. We zero every byte slice we control, but that original string stays in
   memory until the garbage collector reclaims it, and we cannot overwrite it without `unsafe`.
   The stdin prompt has no such problem — it is a `[]byte` all the way through.

3. **Hidden passphrase entry uses `stty`,** so it works on macOS and Linux. On Windows it falls
   back to visible typing rather than failing.

4. **PBKDF2 is not memory-hard.** Argon2id resists GPU and ASIC attack far better. PBKDF2 is what
   the specification for this project required, and it is in the standard library; Argon2 is not.
   Raising `-rounds` is the mitigation available here.

5. **Entropy scanning produces false positives.** Base64 blobs, minified JavaScript, hashes and
   UUIDs all score high. That is inherent to the technique. Raise `-entropy` to trade recall for
   precision.

6. **No protection against a compromised machine.** Bastion protects files at rest. A keylogger,
   a malicious process reading your memory, or a backdoored Go toolchain all defeat it.

---

## Verified benchmarks

Measured on Apple Silicon (M-series, 10 cores), Go 1.27.0, `darwin/arm64`. Reproduce with
`make bench`. Figures vary by 1–2% between runs.

| Operation | Result |
|---|---|
| **Encrypt** (10 MB, streaming) | **3,359 MB/s** |
| **Decrypt** (10 MB, streaming) | **3,628 MB/s** |
| TOTP generate | 674,000 codes/sec (1,493 ns) |
| TOTP verify | 224,000/sec (4,563 ns) |
| Password generate | 243,000/sec (4,144 ns) |
| Shannon entropy (34 chars) | 464 ns, **0 allocations** |
| Secret scanner | 6.08 MB/s |
| PBKDF2 key derivation (100k) | 15.3 ms |

Two of these deserve comment.

**Encryption runs at 3.4 GB/s** because `crypto/aes` uses the CPU's AES instructions. A 1 GB file
encrypts in roughly a third of a second, in constant memory.

**PBKDF2 costs 15.3 ms, and that is the point.** It is five times longer than encrypting an entire
10 MB file. That fixed cost is what makes brute-forcing a passphrase expensive; at `-rounds 600000`
it becomes ~92 ms.

**Coverage: 90.9% of statements**, across 96 tests. The uncovered remainder is unreachable error
handling — disk write failures, a dead system CSPRNG, and TTY-only code paths.

---

## Reproducible builds

Anyone compiling this source gets a byte-identical binary. That is what makes it possible to
verify that a distributed binary matches the published source.

```bash
$ make reproducible

d92be439a418c3fa14d7a2f5decf8de523759c22f12fefbc889ae0409f8b964d  dist/bastion-1
d92be439a418c3fa14d7a2f5decf8de523759c22f12fefbc889ae0409f8b964d  dist/bastion-2
d92be439a418c3fa14d7a2f5decf8de523759c22f12fefbc889ae0409f8b964d  dist/bastion-3

REPRODUCIBLE: all three builds are byte-for-byte identical
              (build 3 came from a different directory, so no host path leaked in)
```

> **Reference hash** (Go 1.27.0, `darwin/arm64`):
> `d92be439a418c3fa14d7a2f5decf8de523759c22f12fefbc889ae0409f8b964d`
>
> The hash is specific to the Go version and target platform. A different Go release or a
> different GOOS/GOARCH will produce a different — but equally reproducible — hash.

**Build 3 is the meaningful one.** Two builds in the same directory would match even if the binary
had that directory's absolute path baked into it. Build 3 is compiled from a copy at a different
path; matching proves `-trimpath` genuinely stripped host paths out.

The flags, and what each removes:

| Flag | Removes |
|---|---|
| `CGO_ENABLED=0` | Any host C toolchain |
| `-trimpath` | Absolute source paths |
| `-buildvcs=false` | Git commit hash and dirty state |
| `-ldflags="-s -w"` | Symbol and DWARF debug tables |
| `-ldflags="-buildid="` | Go's build ID, which otherwise varies |

---

## One-command verification

Everything a reviewer needs, in four commands:

```bash
make build          # compile ./bastion with reproducible flags
make test           # 96 tests with coverage
make reproducible   # prove the build is byte-identical
make audit          # prove the dependency manifest is empty
```

Other targets:

```bash
make test-short     # ~2s pre-commit check, skips heavy payloads
make bench          # benchmarks with allocation counts
make clean          # remove binaries and test artefacts
```

`make audit` output:

```
--- go list -m all ---
bastion
OK: no require block, no external dependencies
```

---

## Project layout

```
bastion.go        908 lines   all production logic
bastion_test.go  1286 lines   96 tests, 8 benchmarks
Makefile                      build, test, bench, reproducible, audit, clean
STDLIB.md                     the eleven dependencies replaced, and how
CLAUDE.md                     the project's hard invariants
go.mod                        module bastion — no require block
```

### Design invariants

1. **Zero external runtime dependencies.** Standard library only.
2. **Single production file.** All logic in `bastion.go`.
3. **Minimal, idiomatic Go.** No wrappers or boilerplate for their own sake.
4. **Fail closed.** Exit `2` on any security failure; zero secret buffers; constant-time compares.
5. **O(1) memory.** Chunked streaming, so file size never dictates memory use.

---

## Requirements

Go 1.22 or newer. No other tooling, no network access, nothing to install.

---

Built for a zero-dependency hackathon, Track E — Security & Crypto Utilities.
