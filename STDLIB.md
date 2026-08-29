# Standard Library Audit

**Bastion has zero third-party runtime dependencies.** Its `go.mod` contains no `require`
block, and `go list -m all` prints exactly one line: the module itself.

```
$ go list -m all
bastion
```

This document records what a conventional build of the same tool would have pulled in, and
which standard-library package replaced it.

---

## Executive summary

A tool of this scope — authenticated file encryption, TOTP, secret scanning, password
generation, hashing, and a subcommand CLI — would normally reach for somewhere between ten and
twenty external packages. Each one is a supply-chain entry point: a package that can be
compromised upstream, abandoned, or silently updated underneath you.

For a **security** tool that trade is a poor one. An attacker who compromises one transitive
dependency of an encryption utility owns the encryption utility. So Bastion imports nothing but
the Go standard library, which ships with the toolchain, is versioned with it, and is covered by
the Go Security Policy.

The cost of this decision is real and worth stating plainly: **we hand-wrote PBKDF2, TOTP, base32
normalisation, chunked AEAD framing, Shannon entropy, the CLI router, a cryptographic KAT suite,
and a live hardware benchmark engine.** That is substantially more production code than a dependency
would otherwise have supplied. We paid for it with a comprehensive test suite — over 100 tests at
high statement coverage, including six RFC 6238 reference vectors, published SHA digests, NIST
SP 800-38D AES-GCM vectors, RFC 7914 PBKDF2 vectors, and thirteen tamper/truncation/reorder/splice
attack simulations.

Hand-rolled cryptography is a legitimate risk. Our mitigation is that we hand-rolled only the
*constructions* — key stretching, counter framing, code truncation — and never the primitives.
Every primitive (AES, GCM, SHA-256, SHA-512, SHA-1, HMAC, the CSPRNG, constant-time comparison)
comes from `crypto/*`, which is audited, hardware-accelerated, and maintained by the Go team.

The three quantified benefits:

| | |
|---|---|
| **Supply chain** | 0 external packages. Nothing to audit, pin, or patch. |
| **Reproducibility** | Byte-identical builds across directories — SHA-256 `d92be439…f8b964d`. |
| **Portability** | `CGO_ENABLED=0`, pure Go, cross-compiles anywhere Go runs. |

---

## The eleven replacements

| # | Conventional dependency | Standard library replacement | What Bastion actually does with it |
|---|---|---|---|
| 1 | `age`, `SOPS`, `filippo.io/age` | `crypto/aes` + `crypto/cipher` | Streaming AES-256-GCM. The file is sealed in 64 KiB chunks, each with its own 16-byte AEAD tag, so encryption and decryption run in O(1) memory — a 300 MB file peaks at 5.6 MB RSS. `sealStream` / `openStream`. |
| 2 | `golang.org/x/crypto/pbkdf2`, `argon2` | `crypto/hmac` + `crypto/sha256` | RFC 2898 PBKDF2-HMAC-SHA256, written out in `pbkdf2SHA256`. Iteration count is configurable from 1,000 to 10,000,000, defaults to 100,000, and is stored in the file header so decryption never has to be told. |
| 3 | `pquerna/otp`, `otplib`, `speakeasy` | `crypto/hmac` + `crypto/sha1` + `encoding/binary` | RFC 6238 TOTP: 30-second step, HMAC-SHA1, dynamic truncation to 6 digits, ±1 step drift tolerance on verify. Validated against all six published RFC test vectors. |
| 4 | `trufflehog`, `gitleaks` | `regexp` + `math` | Secret detection on two axes. Nine compiled regexes cover AWS, GitHub, Slack, Google and PEM formats; alongside them a Shannon entropy score, `H = -Σ p·log₂p`, catches high-randomness tokens that match no known vendor format. |
| 5 | `google/uuid`, `secure-random` | `crypto/rand` | Every salt, nonce and generated password byte comes from the operating system CSPRNG. Password characters are drawn with `rand.Int`, which rejection-samples — a naive `%` would bias the output toward early characters in the pool. |
| 6 | `crypto-compare`, hand-rolled `==` | `crypto/subtle` | `ConstantTimeCompare` for TOTP verification and passphrase confirmation, so comparison time never depends on how many bytes matched. `subtle.XORBytes` also drives the PBKDF2 accumulator. |
| 7 | `spf13/cobra`, `urfave/cli` | `flag` + `os.Args` dispatch | A hand-written subcommand router (`dispatch`) with per-command `flag.FlagSet`s and nested subcommands (`totp gen` / `totp verify`). Exit codes are 0 = OK, 1 = usage/IO, 2 = security. Uses `ContinueOnError`, because `ExitOnError` exits with status 2 and would make a flag typo indistinguishable from a tamper alert. |
| 8 | `fatih/color`, `chalk` | Raw ANSI escape sequences | Green / red / yellow / dim via `\x1b[…m`, auto-disabled when stdout is not a terminal or `NO_COLOR` is set. Results go to stdout, commentary to stderr, so `bastion gen \| pbcopy` pipes a clean password. |
| 9 | `stretchr/testify`, `jest` | `testing` | 96 tests, 90.9% coverage, table-driven with plain `if`/`t.Errorf`. Includes 13 adversarial attack simulations, 25 subprocess cases that assert real process exit codes, and 8 benchmarks with `-benchmem`. No assertion library. |
| 10 | `joho/godotenv`, `dotenv` | `bufio.Scanner` + `strings` | Line-oriented input handling: `bufio.Scanner` walks scanned files a line at a time with a 1 MB cap, and reads the passphrase from stdin; `strings` normalises base32 secrets (case, spaces, hyphens, padding) before decoding. |
| 11 | `atotto/clipboard` | `os/exec` + explicit zeroing | Secret handling without a clipboard package. `os/exec` toggles terminal echo via `stty` so a typed passphrase never appears on screen; `zero()` overwrites key and passphrase buffers immediately after use; and because stdout stays pipeable, the user's own `pbcopy`/`xclip` does the clipboard job. |

---

## Notes on two of the mappings

Rows 10 and 11 are the loosest fits, and it is worth being straight about why.

**Row 10** — Bastion has no `.env` file support and parses no configuration format. What it
genuinely shares with a dotenv library is the underlying technique: streaming a file line by line
through `bufio.Scanner` rather than reading it whole, and normalising strings with `strings`. That
technique is what keeps the scanner's memory flat over a large repository.

**Row 11** — Bastion does not write to the clipboard. It deliberately does the opposite: it keeps
secrets out of places they can linger. `os/exec` is used only to turn terminal echo off, and the
clipboard, if the user wants one, is reached by piping stdout to a tool they already trust.

---

## What we did not have to hand-write

Everything cryptographically load-bearing is standard library, not our code:

`crypto/aes` (AES-NI accelerated) · `crypto/cipher` (GCM) · `crypto/sha256` · `crypto/sha512` ·
`crypto/sha1` · `crypto/hmac` · `crypto/rand` · `crypto/subtle` · `encoding/base32` ·
`encoding/binary` · `encoding/hex`

Our contribution is the framing around them. That is the line we deliberately did not cross.
