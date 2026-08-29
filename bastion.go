// BASTION — a zero-dependency security toolbox.
//
// Standard library only. All production logic lives in this file.
//
// Exit codes: 0 = OK, 1 = argument/IO error, 2 = tamper / security issue / leaked secret.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"os/signal"
)

const (
	saltLen   = 16
	roundsLen = 4 // PBKDF2 iteration count, big-endian uint32
	nonceLen  = 12
	keyLen    = 32 // AES-256
	tagLen    = 16 // GCM tag
	chunkSize = 64 * 1024
	headerLen = saltLen + roundsLen + nonceLen // 32

	// The iteration count travels with the file, so a file always carries the
	// cost needed to open it and dec never needs to be told. The bounds stop a
	// hostile header from turning decryption into a CPU denial of service. A
	// count that has merely been altered needs no special handling: it derives a
	// different key, so authentication fails like any other tampering.
	defaultRounds = 100000 // RFC 2898 baseline required by the spec
	minRounds     = 1000
	maxRounds     = 10000000

	exitOK       = 0
	exitUsage    = 1
	exitSecurity = 2
)

// exitErr carries the process exit code that an error should produce.
// Only main turns one into an os.Exit, which keeps every other function testable.
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

func usagef(format string, a ...any) error { return exitErr{exitUsage, fmt.Sprintf(format, a...)} }
func secf(format string, a ...any) error   { return exitErr{exitSecurity, fmt.Sprintf(format, a...)} }

// errTamper is returned whenever AEAD authentication fails, for any reason.
// The message is deliberately identical in all cases so it leaks nothing about
// which check failed.
var errTamper = exitErr{exitSecurity, "authentication failed: wrong password or the file has been tampered with"}

// errQuiet exits with a code but prints nothing (the flag package already reported).
func errQuiet(code int) error { return exitErr{code, ""} }

// ---------------------------------------------------------------- output

var useColor = os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func green(s string) string  { return paint("1;32", s) }
func red(s string) string    { return paint("1;31", s) }
func yellow(s string) string { return paint("1;33", s) }
func dim(s string) string    { return paint("2", s) }

// Rule: stdout carries only the machine-readable result (a code, a password, a
// digest, a finding). Commentary and warnings go to stderr so output stays pipeable.
func okf(format string, a ...any)   { fmt.Println(green("✔ ") + fmt.Sprintf(format, a...)) }
func warnf(format string, a ...any) { fmt.Fprintln(os.Stderr, yellow("! ")+fmt.Sprintf(format, a...)) }
func notef(format string, a ...any) { fmt.Fprintln(os.Stderr, dim("— "+fmt.Sprintf(format, a...))) }

// fatal is reserved for conditions no caller can recover from — currently only a
// dead system CSPRNG. Refusing to continue without randomness is failing closed.
func fatal(format string, a ...any) {
	fmt.Fprintln(os.Stderr, red("✘ ")+fmt.Sprintf(format, a...))
	os.Exit(exitSecurity)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------- secrets in memory

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatal("system randomness unavailable: %v", err)
	}
	return b
}

var stdin = bufio.NewReader(os.Stdin)

// disableEcho turns off terminal echo so a typed password stays off screen.
// Returns a restore func; a no-op when stdin is not a terminal.
func disableEcho() func() {
	if !isTTY(os.Stdin) {
		return func() {}
	}
	c := exec.Command("stty", "-echo")
	c.Stdin = os.Stdin
	if c.Run() != nil {
		return func() {}
	}
	return func() {
		r := exec.Command("stty", "echo")
		r.Stdin = os.Stdin
		_ = r.Run()
	}
}

func promptPassword(prompt string) ([]byte, error) {
	// On a real Windows console, delegate to PowerShell Read-Host -AsSecureString
	// which renders asterisks instead of echoing keystrokes. The guard on isTTY
	// ensures the PowerShell path is never taken in automated pipelines or tests
	// (where stdin is a pipe, not a terminal), so stdin-piped tests still pass.
	if runtime.GOOS == "windows" && isTTY(os.Stdin) {
		return readPasswordWindows(prompt)
	}
	fmt.Fprint(os.Stderr, prompt)
	restore := disableEcho()
	line, err := stdin.ReadString('\n')
	restore()
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return nil, usagef("could not read password: %v", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// readPasswordWindows reads a password on Windows consoles using PowerShell's
// Read-Host -AsSecureString, which shows asterisks instead of echoing the
// typed characters.  The SecureString is immediately converted back to a plain
// string and captured from the subprocess stdout — it never appears on screen.
// If PowerShell is unavailable the function falls back to a plain buffered read.
func readPasswordWindows(prompt string) ([]byte, error) {
	// PowerShell's Read-Host automatically appends a colon and space.
	cleanPrompt := strings.TrimRight(prompt, ": ")
	// Single-quoted prompt is safe because our prompts contain only printable
	// ASCII without single-quote characters.
	psCmd := `$p = Read-Host -AsSecureString '` + cleanPrompt + `'; ` +
		`[Runtime.InteropServices.Marshal]::PtrToStringAuto(` +
		`[Runtime.InteropServices.Marshal]::SecureStringToBSTR($p))`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	// Stderr is forwarded so any PowerShell error messages reach the user.
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	fmt.Fprintln(os.Stderr) // blank line after the masked input line
	if err != nil {
		// PowerShell unavailable or failed — fall back to a plain buffered read.
		fmt.Fprint(os.Stderr, prompt)
		restore := disableEcho()
		line, rerr := stdin.ReadString('\n')
		restore()
		fmt.Fprintln(os.Stderr)
		if rerr != nil && line == "" {
			return nil, usagef("could not read password: %v", rerr)
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	pw := bytes.TrimRight(out, "\r\n")
	if len(pw) == 0 {
		return nil, usagef("could not read password via PowerShell")
	}
	return pw, nil
}

// resolvePass takes the -pass flag if given, otherwise prompts (twice when confirming).
func resolvePass(flagVal string, confirm bool) ([]byte, error) {
	if flagVal != "" {
		return []byte(flagVal), nil
	}
	pass, err := promptPassword("Password: ")
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, usagef("password must not be empty")
	}
	if !confirm {
		return pass, nil
	}
	again, err := promptPassword("Confirm password: ")
	if err != nil {
		zero(pass)
		return nil, err
	}
	same := subtle.ConstantTimeCompare(pass, again) == 1
	zero(again)
	if !same {
		zero(pass)
		return nil, usagef("passwords do not match")
	}
	return pass, nil
}

// ---------------------------------------------------------------- key derivation

// pbkdf2SHA256 implements PBKDF2-HMAC-SHA256 (RFC 2898).
func pbkdf2SHA256(pass, salt []byte, iter, dkLen int) []byte {
	prf := hmac.New(sha256.New, pass)
	hLen := prf.Size()
	blocks := (dkLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	u := make([]byte, 0, hLen)
	t := make([]byte, hLen)
	var idx [4]byte

	for b := 1; b <= blocks; b++ {
		binary.BigEndian.PutUint32(idx[:], uint32(b))
		prf.Reset()
		prf.Write(salt)
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			subtle.XORBytes(t, t, u)
		}
		dk = append(dk, t...)
	}
	zero(t)
	zero(u[:cap(u)])
	return dk[:dkLen]
}

// deriveGCM turns a passphrase and salt into a ready AES-256-GCM cipher.
// The intermediate key is zeroed before returning.
func deriveGCM(pass, salt []byte, rounds int) (cipher.AEAD, error) {
	key := pbkdf2SHA256(pass, salt, rounds, keyLen)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ---------------------------------------------------------------- streaming AEAD
//
// Wire format: [16-byte salt][4-byte rounds][12-byte base nonce][chunk 0][chunk 1]...
// Each chunk is up to 64 KiB of plaintext sealed with AES-256-GCM (+16-byte tag).
//
// Per-chunk nonce = base XOR (0x000000 || counter[8] || finalFlag[1]).
// The counter makes reordering fail; the final flag makes truncation fail.

func chunkNonce(base []byte, counter uint64, final bool) []byte {
	n := make([]byte, nonceLen)
	copy(n, base)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	for i := 0; i < 8; i++ {
		n[3+i] ^= c[i]
	}
	if final {
		n[nonceLen-1] ^= 1
	}
	return n
}

// atEOF reports whether r has no bytes left.
func atEOF(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	return err != nil
}

// sealStream is the pure encryption loop: no key derivation, no header.
// Split out so benchmarks can measure cipher throughput on its own.
func sealStream(gcm cipher.AEAD, base []byte, in *bufio.Reader, out io.Writer) error {
	buf := make([]byte, chunkSize)
	ct := make([]byte, 0, chunkSize+tagLen)
	defer zero(buf)

	for counter := uint64(0); ; counter++ {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		final := n < chunkSize || atEOF(in)
		ct = gcm.Seal(ct[:0], chunkNonce(base, counter, final), buf[:n], nil)
		if _, err := out.Write(ct); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

// openStream is the pure decryption loop. Any authentication failure returns
// errTamper and nothing already written can be trusted by the caller.
func openStream(gcm cipher.AEAD, base []byte, in *bufio.Reader, out io.Writer) error {
	buf := make([]byte, chunkSize+tagLen)
	pt := make([]byte, 0, chunkSize)
	defer zero(buf)

	for counter := uint64(0); ; counter++ {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n < tagLen {
			return errTamper // truncated: a chunk cannot be smaller than its tag
		}
		final := n < len(buf) || atEOF(in)
		pt, err = gcm.Open(pt[:0], chunkNonce(base, counter, final), buf[:n], nil)
		if err != nil {
			zero(pt[:cap(pt)])
			return errTamper
		}
		if _, err := out.Write(pt); err != nil {
			return err
		}
		if final {
			zero(pt[:cap(pt)])
			return nil
		}
	}
}

func encryptStream(in *bufio.Reader, out io.Writer, pass []byte, rounds int) error {
	salt := randBytes(saltLen)
	base := randBytes(nonceLen)

	gcm, err := deriveGCM(pass, salt, rounds)
	if err != nil {
		return err
	}
	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, salt...)
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(rounds))
	hdr = append(hdr, base...)
	if _, err := out.Write(hdr); err != nil {
		return err
	}
	return sealStream(gcm, base, in, out)
}

func decryptStream(in *bufio.Reader, out io.Writer, pass []byte) error {
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(in, hdr); err != nil {
		return errTamper // too short to even hold a header
	}
	rounds := int(binary.BigEndian.Uint32(hdr[saltLen : saltLen+roundsLen]))
	if rounds < minRounds || rounds > maxRounds {
		return secf("refusing file: header declares %d PBKDF2 rounds, outside the accepted %d..%d",
			rounds, minRounds, maxRounds)
	}
	gcm, err := deriveGCM(pass, hdr[:saltLen], rounds)
	if err != nil {
		return err
	}
	return openStream(gcm, hdr[saltLen+roundsLen:], in, out)
}

// runCrypt wires files to the streaming core.
//
// Atomic guarantee: all output is written to <outPath>.tmp first. The temp
// file is renamed to <outPath> only after the final AEAD tag is verified
// (enc) or the complete ciphertext authenticated (dec). On any error the
// temp file is removed, so the caller never sees a partial or
// unauthenticated output file at the destination path.
func runCrypt(inPath, outPath string, pass []byte, encrypt bool, rounds int, wipeSource bool) error {
	src, err := os.Open(inPath)
	if err != nil {
		return usagef("cannot open input: %v", err)
	}
	defer src.Close()

	// Write to a temp file so outPath is only ever complete + authenticated.
	tmpPath := outPath + ".tmp"
	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return usagef("cannot create output: %v", err)
	}

	w := bufio.NewWriter(dst)
	if encrypt {
		err = encryptStream(bufio.NewReaderSize(src, chunkSize), w, pass, rounds)
	} else {
		err = decryptStream(bufio.NewReaderSize(src, chunkSize+tagLen), w, pass)
	}
	if err == nil {
		err = w.Flush()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}

	if err != nil {
		os.Remove(tmpPath) // fail closed: never leave a partial temp file behind
		var e exitErr
		if errors.As(err, &e) {
			return err
		}
		return usagef("%v", err)
	}

	// AEAD tag fully verified — atomically publish the authenticated output.
	if rerr := os.Rename(tmpPath, outPath); rerr != nil {
		os.Remove(tmpPath)
		return usagef("cannot finalize output: %v", rerr)
	}

	fi, _ := os.Stat(outPath)
	if encrypt {
		okf("Encrypted %s → %s (%d bytes, %d PBKDF2 rounds)", inPath, outPath, fi.Size(), rounds)
	} else {
		okf("Decrypted %s → %s (%d bytes)", inPath, outPath, fi.Size())
	}
	
	src.Close() // Explicit close so Windows lets us wipe it
	if wipeSource && encrypt {
		if err := wipeFile(inPath); err != nil {
			return usagef("encryption succeeded, but failed to wipe source: %v", err)
		}
	}
	return nil
}

// wipeFile securely overwrites a file with random bytes, then zeroes, then deletes it.
func wipeFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return usagef("cannot wipe non-regular file: %s", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	size := fi.Size()
	
	// Pass 1: Random bytes
	buf := make([]byte, 32*1024)
	for written := int64(0); written < size; {
		chunk := int64(len(buf))
		if size-written < chunk {
			chunk = size - written
		}
		rand.Read(buf[:chunk]) // crypto/rand
		if _, err := f.Write(buf[:chunk]); err != nil {
			f.Close()
			return err
		}
		written += chunk
	}
	f.Sync()
	
	// Pass 2: Zeroes
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return err
	}
	zero(buf)
	for written := int64(0); written < size; {
		chunk := int64(len(buf))
		if size-written < chunk {
			chunk = size - written
		}
		if _, err := f.Write(buf[:chunk]); err != nil {
			f.Close()
			return err
		}
		written += chunk
	}
	f.Sync()
	f.Close()
	return os.Remove(path)
}

// ---------------------------------------------------------------- TOTP (RFC 6238)

const totpStep int64 = 30

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	if s == "" {
		return nil, errors.New("secret is empty")
	}
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(s)
}

// totpAt returns the 6-digit code for a base32 secret at a given Unix time.
func totpAt(secret string, unix int64) (string, error) {
	key, err := decodeBase32(secret)
	if err != nil {
		return "", usagef("invalid base32 secret: %v", err)
	}
	defer zero(key)

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(unix/totpStep))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// totpVerify checks code against the current step and ±1 neighbour, in constant
// time, with no early exit.
func totpVerify(secret, code string, unix int64) (bool, error) {
	given := []byte(strings.TrimSpace(code))
	match := 0
	for drift := int64(-1); drift <= 1; drift++ {
		want, err := totpAt(secret, unix+drift*totpStep)
		if err != nil {
			return false, err
		}
		match |= subtle.ConstantTimeCompare(given, []byte(want))
	}
	return match == 1, nil
}

func runLiveTOTP(secret string) error {
	// Pre-check the secret
	if _, err := totpAt(secret, time.Now().Unix()); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+dim("Live countdown — press [Enter] or Ctrl+C to exit"))
	fmt.Fprintln(os.Stderr)

	done := make(chan struct{})
	go func() {
		stdin.ReadString('\n')
		close(done)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	const barCells = 24
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Initial print immediately before ticking
	for {
		now := time.Now().Unix()
		secsLeft := totpStep - now%totpStep
		code, _ := totpAt(secret, now)
		
		formatted := fmt.Sprintf("%s %s", code[:3], code[3:])
		filled := int(secsLeft * barCells / totpStep)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barCells-filled)

		var urgency string
		if secsLeft <= 5 {
			urgency = red(fmt.Sprintf("%2ds left", secsLeft))
		} else {
			urgency = dim(fmt.Sprintf("%2ds left", secsLeft))
		}
		fmt.Fprintf(os.Stderr, "\r  %s  [%s]  %s   ", green(formatted), bar, urgency)

		select {
		case <-done:
			fmt.Fprintln(os.Stderr)
			return nil
		case <-sig:
			fmt.Fprintln(os.Stderr)
			return nil
		case <-ticker.C:
		}
	}
}

func cmdTOTPGen(args []string) error {
	fl := flag.NewFlagSet("totp gen", flag.ContinueOnError)
	secret := fl.String("secret", "", "base32-encoded shared secret")
	liveFlag := fl.Bool("live", false, "run interactive live-ticking clock")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	// Accept the secret as the first positional argument when -secret is omitted.
	if *secret == "" && fl.NArg() > 0 {
		*secret = fl.Arg(0)
	}
	if *secret == "" {
		return usagef("totp gen requires -secret or a positional argument")
	}

	if *liveFlag || isTTY(os.Stdout) {
		return runLiveTOTP(*secret)
	}

	now := time.Now().Unix()
	code, err := totpAt(*secret, now)
	if err != nil {
		return err
	}
	fmt.Println(code) // plain code
	return nil
}

func cmdTOTPVerify(args []string) error {
	fl := flag.NewFlagSet("totp verify", flag.ContinueOnError)
	secret := fl.String("secret", "", "base32-encoded shared secret")
	code := fl.String("code", "", "6-digit code to check")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	// Accept secret and code as positional arguments when flags are omitted.
	// Order: posArgs[0] = secret, posArgs[1] = code.
	pos := fl.Args()
	if *secret == "" && len(pos) > 0 {
		*secret = pos[0]
		pos = pos[1:]
	}
	if *code == "" && len(pos) > 0 {
		*code = pos[0]
	}
	if *secret == "" || *code == "" {
		return usagef("totp verify requires -secret and -code (or two positional arguments)")
	}

	ok, err := totpVerify(*secret, *code, time.Now().Unix())
	if err != nil {
		return err
	}
	if !ok {
		return secf("INVALID code")
	}
	okf("VALID code (within ±1 time step)")
	return nil
}

// ---------------------------------------------------------------- secret scanner

var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS Access Key ID", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws[^\n]{0,24}?(?:secret|private)[^\n]{0,24}?['"]([A-Za-z0-9/+=]{40})['"]`)},
	{"GitHub Token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"GitHub Fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"Slack Token", regexp.MustCompile(`\bxox[baprse]-[A-Za-z0-9-]{10,}\b`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}`)},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)}, // no trailing \b: keys may end in '-'
	{"Generic Bearer Token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]{24,}`)},
}

var tokenRE = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)

var skipDirs = map[string]bool{
	".git": true, ".svn": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "target": true, ".venv": true, "venv": true,
	"__pycache__": true, ".idea": true, ".next": true, ".cache": true,
}

var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true,
	".webp": true, ".svg": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true,
	".bz2": true, ".xz": true, ".7z": true, ".mp3": true, ".mp4": true, ".mov": true,
	".avi": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".a": true, ".o": true,
	".class": true, ".jar": true, ".wasm": true, ".pyc": true, ".lock": true, ".sum": true,
}

const maxScanBytes = 8 << 20 // skip anything larger than 8 MiB

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// mixedAlnum keeps the entropy check off prose and off pure-hex hashes.
func mixedAlnum(s string) bool {
	var letter, digit bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letter = true
		}
	}
	return letter && digit
}

func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-4:]
}

func looksBinary(f *os.File) bool {
	var head [512]byte
	n, _ := f.Read(head[:])
	f.Seek(0, io.SeekStart)
	return bytes.IndexByte(head[:n], 0) >= 0
}

// scanFile reports findings to w and returns how many it found.
func scanFile(w io.Writer, path string, threshold float64) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	if looksBinary(f) {
		return 0
	}

	found := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		hit := false

		for _, p := range patterns {
			if m := p.re.FindString(text); m != "" {
				fmt.Fprintf(w, "%s %s:%d  %s  %s\n",
					red("LEAK"), path, line, red(p.name), dim(redact(m)))
				found++
				hit = true
			}
		}
		if hit {
			continue // one report per line is enough
		}
		for _, tok := range tokenRE.FindAllString(text, -1) {
			if !mixedAlnum(tok) {
				continue
			}
			if h := shannon(tok); h >= threshold {
				fmt.Fprintf(w, "%s %s:%d  %s  %s\n",
					yellow("HIGH"), path, line,
					yellow(fmt.Sprintf("High entropy %.2f bits/char", h)), dim(redact(tok)))
				found++
				break // one entropy report per line
			}
		}
	}
	return found
}

// scanDir walks dir and reports every finding to w, returning findings and files scanned.
func scanDir(w io.Writer, dir string, threshold float64) (found, files int, err error) {
	ignoreList := map[string]bool{}
	if ignoreEnv := os.Getenv("BASTION_SCAN_IGNORE"); ignoreEnv != "" {
		for _, name := range strings.Split(ignoreEnv, ",") {
			if n := strings.TrimSpace(name); n != "" {
				ignoreList[n] = true
			}
		}
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if ignoreList[d.Name()] {
			return nil
		}
		if !d.Type().IsRegular() || skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if fi, e := d.Info(); e != nil || fi.Size() > maxScanBytes {
			return nil
		}
		files++
		found += scanFile(w, path, threshold)
		return nil
	})
	return found, files, err
}

func cmdScan(args []string) error {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fl.String("dir", "", "directory to scan recursively (default: current directory)")
	threshold := fl.Float64("entropy", 4.5, "Shannon entropy threshold in bits per character")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	// Accept the directory as a positional argument; fall back to ".".
	if *dir == "" {
		if fl.NArg() > 0 {
			*dir = fl.Arg(0)
		} else {
			*dir = "."
		}
	}

	info, err := os.Stat(*dir)
	if err != nil || !info.IsDir() {
		return usagef("not a directory: %s", *dir)
	}

	total, files, err := scanDir(os.Stdout, *dir, *threshold)
	if err != nil {
		return usagef("scan failed: %v", err)
	}

	notef("scanned %d files in %s", files, *dir)
	if total > 0 {
		return secf("%d potential secret(s) found", total)
	}
	okf("No secrets found")
	return nil
}

// ---------------------------------------------------------------- password generator

const (
	charLower   = "abcdefghijklmnopqrstuvwxyz"
	charUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charDigits  = "0123456789"
	charSymbols = "!@#$%^&*()-_=+[]{};:,.<>?"
)

// pick returns one uniformly random byte from set (no modulo bias).
func pick(set string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		fatal("system randomness unavailable: %v", err)
	}
	return set[n.Int64()]
}

func containsEach(pw []byte, classes []string) bool {
	for _, set := range classes {
		if !bytes.ContainsAny(pw, set) {
			return false
		}
	}
	return true
}

// genPassword returns a password of the given length containing at least one
// character from every requested class.
func genPassword(length int, symbols bool) ([]byte, []string) {
	classes := []string{charLower, charUpper, charDigits}
	if symbols {
		classes = append(classes, charSymbols)
	}
	pool := strings.Join(classes, "")

	pw := make([]byte, length)
	for {
		for i := range pw {
			pw[i] = pick(pool)
		}
		if containsEach(pw, classes) {
			return pw, classes
		}
	}
}

func cmdGen(args []string) error {
	fl := flag.NewFlagSet("gen", flag.ContinueOnError)
	length := fl.Int("len", 20, "password length (minimum 8)")
	symbols := fl.Bool("symbols", false, "include punctuation symbols")
	copyFlag := fl.Bool("copy", false, "copy password to clipboard")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if *length < 8 {
		return usagef("-len must be at least 8")
	}

	pw, classes := genPassword(*length, *symbols)
	pool := strings.Join(classes, "")

	fmt.Println(green(string(pw))) // stdout: just the password
	notef("%d chars, ~%.0f bits of entropy", *length, float64(*length)*math.Log2(float64(len(pool))))
	if *copyFlag {
		if copyToClipboard(string(pw)) {
			okf("Copied to clipboard!")
		} else {
			warnf("Clipboard unavailable")
		}
	}
	zero(pw)
	return nil
}

// ---------------------------------------------------------------- hashing

func newHash(algo string) (hash.Hash, error) {
	switch strings.ToLower(algo) {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, usagef("unknown -algo %q (use sha256 or sha512)", algo)
}

// hashFile streams a file through h and returns the digest as lowercase hex.
func hashFile(path, algo string) (string, error) {
	h, err := newHash(algo)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", usagef("cannot open file: %v", err)
	}
	defer f.Close()

	if _, err := io.Copy(h, bufio.NewReaderSize(f, chunkSize)); err != nil {
		return "", usagef("read error: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func cmdHash(args []string) error {
	fl := flag.NewFlagSet("hash", flag.ContinueOnError)
	path := fl.String("file", "", "file to hash")
	algo := fl.String("algo", "sha256", "sha256 or sha512")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	// Accept the file path as the first positional argument when -file is omitted.
	if *path == "" && fl.NArg() > 0 {
		*path = fl.Arg(0)
	}
	if *path == "" {
		return usagef("hash requires -file or a positional argument")
	}

	sum, err := hashFile(*path, *algo)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", green(sum), *path)
	return nil
}

// ---------------------------------------------------------------- cryptographic self-diagnostics (doctor)

// katPBKDF2 validates PBKDF2-HMAC-SHA256 against the RFC 7914 §11 test vector:
// P="password", S="salt", c=1, dkLen=32.
func katPBKDF2() error {
	// RFC 7914 §11 first test vector: P="password", S="salt", c=1, dkLen=32
	// Computed from the PBKDF2-HMAC-SHA256 specification and cross-verified
	// against the Go standard library's implementation.
	want, _ := hex.DecodeString("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	got := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32)
	if !bytes.Equal(got, want) {
		return fmt.Errorf("PBKDF2 KAT failed: got %x, want %x", got, want)
	}
	return nil
}

// katAESGCM validates AES-256-GCM against NIST SP 800-38D test vector
// (Test Case 14 from the NIST GCM Test Vectors document).
func katAESGCM() error {
	// NIST SP 800-38D, Appendix B, Test Case 14
	// Key: 32 zero bytes, IV: 12 zero bytes, PT: empty, AAD: none => CT: empty, Tag: 530f8afbc74536b9a963b4f1c4cb738b
	keyHex := "0000000000000000000000000000000000000000000000000000000000000000"
	ivHex := "000000000000000000000000"
	wantTagHex := "530f8afbc74536b9a963b4f1c4cb738b"

	keyBytes, _ := hex.DecodeString(keyHex)
	ivBytes, _ := hex.DecodeString(ivHex)
	wantTag, _ := hex.DecodeString(wantTagHex)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("AES-256-GCM KAT: cipher init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("AES-256-GCM KAT: GCM init failed: %v", err)
	}
	// Seal empty plaintext: the result is just the 16-byte authentication tag.
	sealed := gcm.Seal(nil, ivBytes, nil, nil)
	if len(sealed) != 16 {
		return fmt.Errorf("AES-256-GCM KAT: sealed length = %d, want 16", len(sealed))
	}
	if !bytes.Equal(sealed, wantTag) {
		return fmt.Errorf("AES-256-GCM KAT: tag mismatch: got %x, want %x", sealed, wantTag)
	}
	return nil
}

// katTOTP validates RFC 6238 TOTP against the published SHA-1 reference vector.
func katTOTP() error {
	// RFC 6238 Appendix B: secret = ASCII "12345678901234567890", T=59, want="287082" (6-digit)
	const (
		doctorSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "12345678901234567890"
		doctorT      = int64(59)
		doctorWant   = "287082"
	)
	got, err := totpAt(doctorSecret, doctorT)
	if err != nil {
		return fmt.Errorf("TOTP KAT: %v", err)
	}
	if got != doctorWant {
		return fmt.Errorf("TOTP KAT: got %s, want %s", got, doctorWant)
	}
	return nil
}

// katTamper verifies that flipping a single ciphertext byte causes AEAD authentication failure.
func katTamper() error {
	plain := []byte("bastion tamper resistance test")
	var buf bytes.Buffer
	in := bufio.NewReaderSize(bytes.NewReader(plain), chunkSize)
	if err := encryptStream(in, &buf, []byte("tamper-test-key"), minRounds); err != nil {
		return fmt.Errorf("tamper KAT: encrypt: %v", err)
	}
	ct := buf.Bytes()
	// Flip the last byte of the ciphertext (which is inside the AEAD tag).
	ct[len(ct)-1] ^= 0xFF
	var out bytes.Buffer
	err := decryptStream(bufio.NewReaderSize(bytes.NewReader(ct), chunkSize+tagLen), &out, []byte("tamper-test-key"))
	if err == nil {
		return fmt.Errorf("tamper KAT: decryption succeeded on corrupted ciphertext — FAIL OPEN")
	}
	if err != error(errTamper) {
		return fmt.Errorf("tamper KAT: expected errTamper, got: %v", err)
	}
	return nil
}

// katMemHygiene asserts that the zero() routine wipes a buffer to 0x00.
func katMemHygiene() error {
	buf := []byte("this is a secret password that must be erased")
	zero(buf)
	for i, b := range buf {
		if b != 0x00 {
			return fmt.Errorf("memory hygiene KAT: byte[%d] = 0x%02x after zero(), want 0x00", i, b)
		}
	}
	return nil
}

// katCSPRNG validates that crypto/rand is functional and produces non-zero entropy.
func katCSPRNG() error {
	const n = 64
	b1 := make([]byte, n)
	b2 := make([]byte, n)
	if _, err := rand.Read(b1); err != nil {
		return fmt.Errorf("CSPRNG KAT: rand.Read failed: %v", err)
	}
	if _, err := rand.Read(b2); err != nil {
		return fmt.Errorf("CSPRNG KAT: rand.Read failed on second call: %v", err)
	}
	// Two independent reads must not be identical (astronomically improbable with a working CSPRNG).
	if bytes.Equal(b1, b2) {
		return fmt.Errorf("CSPRNG KAT: two consecutive rand.Read calls returned identical bytes")
	}
	// All-zero output from a working CSPRNG is impossible for 64 bytes.
	allZero := true
	for _, b := range b1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("CSPRNG KAT: rand.Read returned all-zero bytes")
	}
	return nil
}

// cmdDoctor runs the full cryptographic self-diagnostic suite and prints a summary card.
func cmdDoctor(_ []string) error {
	type result struct {
		label string
		err   error
	}

	tests := []struct {
		label string
		fn    func() error
	}{
		{"PBKDF2 Key Derivation (RFC 2898)", katPBKDF2},
		{"AES-256-GCM Authenticated Encryption (NIST SP 800-38D)", katAESGCM},
		{"RFC 6238 TOTP 2FA Engine", katTOTP},
		{"Active Tamper-Resistance & Fail-Closed AEAD", katTamper},
		{"Memory Hygiene & Buffer Sanitization", katMemHygiene},
		{"Hardware Entropy Source (CSPRNG)", katCSPRNG},
	}

	results := make([]result, len(tests))
	all := true
	for i, tc := range tests {
		results[i] = result{label: tc.label, err: tc.fn()}
		if results[i].err != nil {
			all = false
		}
	}

	// Print the summary card.
	const W = 48
	rule := strings.Repeat("─", W+4)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "╭"+rule+"╮")
	titleIcon := green("✔")
	titleText := "BASTION CRYPTOGRAPHIC SELF-DIAGNOSTICS"
	if !all {
		titleIcon = red("✘")
		titleText = "DIAGNOSTICS FAILED — SEE BELOW"
	}
	titlePad := W - 3 - len(titleText)
	if titlePad < 0 {
		titleText = titleText[:W-3]
		titlePad = 0
	}
	fmt.Fprintln(os.Stderr, "│  "+titleIcon+"  "+titleText+strings.Repeat(" ", titlePad)+"  │")
	fmt.Fprintln(os.Stderr, "├"+rule+"┤")

	for _, r := range results {
		var icon, status string
		if r.err == nil {
			icon = green("✔")
			status = green("[PASS]")
		} else {
			icon = red("✘")
			status = red("[FAIL]")
		}
		// Truncate label to fit the card width.
		lbl := r.label
		maxLbl := W - 10 // icon(1)+sp(1)+status(6)+sp(2) = 10
		if len(lbl) > maxLbl {
			lbl = lbl[:maxLbl-1] + "…"
		}
		line := icon + " " + status + "  " + lbl
		lineLen := 1 + 1 + 6 + 2 + len(lbl)
		pad := W - lineLen
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintln(os.Stderr, "│  "+line+strings.Repeat(" ", pad)+"  │")
		if r.err != nil {
			errLine := "   ↳ " + r.err.Error()
			if len(errLine) > W {
				errLine = errLine[:W-1] + "…"
			}
			errPad := W - len(errLine)
			if errPad < 0 {
				errPad = 0
			}
			fmt.Fprintln(os.Stderr, "│  "+red(errLine)+strings.Repeat(" ", errPad)+"  │")
		}
	}

	fmt.Fprintln(os.Stderr, "╰"+rule+"╯")
	fmt.Fprintln(os.Stderr)

	if !all {
		return secf("one or more cryptographic self-tests FAILED")
	}
	return nil
}

// ---------------------------------------------------------------- live hardware benchmarks (bench)

// benchResult holds the outcome of a single benchmark run.
type benchResult struct {
	name    string
	result  string
	elapsed time.Duration
}

// runBench times fn over a minimum wall-clock duration, returning throughput or ops/sec.
func runBench(minDur time.Duration, fn func(n int)) (iters int, elapsed time.Duration) {
	// Warm-up
	fn(1)
	// Calibration: double n until we hit minDur.
	n := 1
	for {
		t0 := time.Now()
		fn(n)
		elapsed = time.Since(t0)
		if elapsed >= minDur {
			iters = n
			return
		}
		if elapsed > 0 {
			// Estimate how many iterations we need.
			n = int(float64(n) * float64(minDur) / float64(elapsed) * 1.1)
			if n < 1 {
				n = 1
			}
		} else {
			n *= 2
		}
	}
}

// cmdBench runs the live hardware performance benchmark suite.
func cmdBench(_ []string) error {
	const benchDur = 500 * time.Millisecond
	const benchDataMB = 32 // data size for stream benchmarks (MB)
	const benchData = benchDataMB << 20

	var results []benchResult

	fmt.Fprintln(os.Stderr, "\n  "+dim("Running benchmarks… (each ~500 ms)"))

	// 1. AES-256-GCM Encryption Throughput
	{
		plain := make([]byte, benchData)
		rand.Read(plain) //nolint:errcheck
		key := make([]byte, keyLen)
		rand.Read(key) //nolint:errcheck
		base := make([]byte, nonceLen)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)

		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				sealStream(gcm, base, bufio.NewReaderSize(bytes.NewReader(plain), chunkSize), io.Discard) //nolint:errcheck
			}
		})
		mbps := float64(int64(iters)*benchData) / elapsed.Seconds() / (1 << 20)
		results = append(results, benchResult{
			name:    "AES-256-GCM Encrypt",
			result:  fmt.Sprintf("%.1f MB/s", mbps),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// 2. AES-256-GCM Decryption Throughput
	{
		plain := make([]byte, benchData)
		rand.Read(plain) //nolint:errcheck
		key := make([]byte, keyLen)
		rand.Read(key) //nolint:errcheck
		base := make([]byte, nonceLen)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)

		// Pre-seal the data for decryption benchmarking.
		var sealBuf bytes.Buffer
		sealStream(gcm, base, bufio.NewReaderSize(bytes.NewReader(plain), chunkSize), &sealBuf) //nolint:errcheck
		sealed := sealBuf.Bytes()

		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				openStream(gcm, base, bufio.NewReaderSize(bytes.NewReader(sealed), chunkSize+tagLen), io.Discard) //nolint:errcheck
			}
		})
		mbps := float64(int64(iters)*benchData) / elapsed.Seconds() / (1 << 20)
		results = append(results, benchResult{
			name:    "AES-256-GCM Decrypt",
			result:  fmt.Sprintf("%.1f MB/s", mbps),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// 3. TOTP Generation ops/sec
	{
		const totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				totpAt(totpSecret, int64(i)*30) //nolint:errcheck
			}
		})
		ops := float64(iters) / elapsed.Seconds()
		results = append(results, benchResult{
			name:    "TOTP Generation",
			result:  fmt.Sprintf("%.0f ops/sec", ops),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// 4. Password Generation ops/sec
	{
		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				pw, _ := genPassword(20, true)
				zero(pw)
			}
		})
		ops := float64(iters) / elapsed.Seconds()
		results = append(results, benchResult{
			name:    "Password Generation",
			result:  fmt.Sprintf("%.0f ops/sec", ops),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// 5. SHA-256 Streaming Throughput
	{
		data := make([]byte, benchData)
		rand.Read(data) //nolint:errcheck
		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				h := sha256.New()
				_, _ = io.Copy(h, bufio.NewReaderSize(bytes.NewReader(data), chunkSize))
				h.Sum(nil)
			}
		})
		mbps := float64(int64(iters)*benchData) / elapsed.Seconds() / (1 << 20)
		results = append(results, benchResult{
			name:    "SHA-256 Hashing",
			result:  fmt.Sprintf("%.1f MB/s", mbps),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// 6. Shannon Entropy Calculation Speed
	{
		tok := "aZ9kQ2mX7pL4vB8nR3tY6wE1sD5fG0hJcV"
		iters, elapsed := runBench(benchDur, func(n int) {
			for i := 0; i < n; i++ {
				_ = shannon(tok)
			}
		})
		nsPerOp := float64(elapsed.Nanoseconds()) / float64(iters)
		results = append(results, benchResult{
			name:    "Shannon Entropy",
			result:  fmt.Sprintf("%.1f ns/op", nsPerOp),
			elapsed: elapsed / time.Duration(iters),
		})
	}

	// Print benchmark card.
	const W = 48
	rule := strings.Repeat("─", W+4)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "╭"+rule+"╮")
	titleText := "LIVE HARDWARE BENCHMARK RESULTS"
	titlePad := W - 3 - len(titleText)
	if titlePad < 0 {
		titlePad = 0
	}
	fmt.Fprintln(os.Stderr, "│  "+green("⚡")+"  "+titleText+strings.Repeat(" ", titlePad)+"  │")
	fmt.Fprintln(os.Stderr, "├"+rule+"┤")

	for _, r := range results {
		nameFmt := fmt.Sprintf("%-22s", r.name)
		valFmt := fmt.Sprintf("%-16s", r.result)
		durFmt := dim(fmtDur(r.elapsed) + "/op")
		line := green("▶")+" "+nameFmt+" "+valFmt
		// visible length: 1+1+22+1+16 = 41
		pad := W - 41
		if pad < 0 {
			pad = 0
		}
		_ = durFmt // used in card line below
		lineWithDur := green("▶") + " " + nameFmt + " " + valFmt
		_ = lineWithDur
		fmt.Fprintln(os.Stderr, "│  "+line+strings.Repeat(" ", pad)+"  │")
		// sub-row: show per-op time in dim
		subLine := fmt.Sprintf("  %-22s %s", "", durFmt)
		subVis := 2 + 22 + 1 + len(fmtDur(r.elapsed)+"/op")
		subPad := W - subVis
		if subPad < 0 {
			subPad = 0
		}
		fmt.Fprintln(os.Stderr, "│  "+subLine+strings.Repeat(" ", subPad)+"  │")
	}

	fmt.Fprintln(os.Stderr, "╰"+rule+"╯")
	fmt.Fprintln(os.Stderr)
	return nil
}

// ---------------------------------------------------------------- interactive TUI menu

func drawDashboard() {
	clearScreen()
	fmt.Fprintln(os.Stderr, green("\n╭──────────────────────────────────────────────────────╮"))
	fmt.Fprintln(os.Stderr, green("│")+"   BASTION  —  Zero-Dependency Security Toolbox       "+green("│"))
	fmt.Fprintln(os.Stderr, green("│")+"   ┃ AES-256-GCM ┃ PBKDF2-SHA-256 ┃ CSPRNG ┃          "+green("│"))
	fmt.Fprintln(os.Stderr, green("├──────────────────────────────────────────────────────┤"))
	fmt.Fprintln(os.Stderr, green("│  ")+"VAULT & FILE OPERATIONS                             "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[1/E]")+" Encrypt File         "+yellow("[2/D]")+" Decrypt File     "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[3/V]")+" View Encrypted       "+yellow("[4/M]")+" In-Place Edit    "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[5/W]")+" Wipe File                                   "+green("│"))
	fmt.Fprintln(os.Stderr, green("│                                                      │"))
	fmt.Fprintln(os.Stderr, green("│  ")+"CREDENTIALS & AUDITING                              "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[6/T]")+" 2FA TOTP             "+yellow("[7/S]")+" Secret Scanner   "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[8/G]")+" Password Gen         "+yellow("[9/H]")+" Hash File        "+green("│"))
	fmt.Fprintln(os.Stderr, green("├──────────────────────────────────────────────────────┤"))
	fmt.Fprintln(os.Stderr, green("│  ")+"DIAGNOSTICS                                         "+green("│"))
	fmt.Fprintln(os.Stderr, green("│    ")+yellow("[K/D]")+" Crypto Doctor (Self-Test)"+yellow("[B]")+" Benchmarks    "+green("│"))
	fmt.Fprintln(os.Stderr, green("├──────────────────────────────────────────────────────┤"))
	fmt.Fprintln(os.Stderr, green("│  ")+yellow("[?]")+" CLI Help                 "+yellow("[0/Q]")+" Quit             "+green("│"))
	fmt.Fprintln(os.Stderr, green("╰──────────────────────────────────────────────────────╯"))
	fmt.Fprint(os.Stderr, "  Choice: ")
}

// clearScreen sends the ANSI "cursor home + erase display" sequence to stderr.
// Only called inside cmdMenu which already guards on isTTY, so non-interactive
// pipelines and automated tests never see this sequence.
func clearScreen() { fmt.Fprint(os.Stderr, "\x1b[H\x1b[2J") }

// fmtSize formats a byte count as a human-readable string.
func fmtSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// fmtDur formats a duration as "142 ms" or "1.24 s".
func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

// drawCard renders a rounded result card to stderr.
//
// The card has a fixed visible width of 54 characters:
//   ╭────────────────────────────────────────────────────╮
//   │  content (up to 48 visible chars)              │
//   ╰────────────────────────────────────────────────────╯
func drawCard(title string, rows [][2]string, ok bool) {
	const W = 48 // visible content width
	rule := strings.Repeat("─", W+4)

	fmt.Fprintln(os.Stderr, "╭"+rule+"╮")

	// Status header row
	var icon string
	if ok {
		icon = green("✔")
	} else {
		icon = red("✘")
	}
	// visible: 1(icon)+2(sp)+len(title); pad the title portion to (W-3)
	titlePad := W - 3 - len(title)
	if titlePad < 0 {
		title = title[:W-3]
		titlePad = 0
	}
	fmt.Fprintln(os.Stderr, "│  "+icon+"  "+title+strings.Repeat(" ", titlePad)+"  │")
	fmt.Fprintln(os.Stderr, "├"+rule+"┤")

	// Data rows
	for _, r := range rows {
		line := fmt.Sprintf("%-12s%s", r[0], r[1])
		if len(line) > W {
			line = line[:W]
		}
		pad := W - len(line)
		fmt.Fprintln(os.Stderr, "│  "+line+strings.Repeat(" ", pad)+"  │")
	}

	fmt.Fprintln(os.Stderr, "╰"+rule+"╯")
}

// pauseForEnter waits for the user to press Enter before redrawing the menu.
func pauseForEnter() {
	fmt.Fprint(os.Stderr, "\n  "+dim("Press [Enter] to return to dashboard..."))
	stdin.ReadString('\n') //nolint:errcheck
	fmt.Fprintln(os.Stderr)
}

// menuPromptStr displays a labelled input prompt with an optional default value
// and reads one line from stdin, returning the default when the user hits Enter.
func menuPromptStr(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(os.Stderr, "  %s %s ", label, dim("["+def+"]:"))
	} else {
		fmt.Fprintf(os.Stderr, "  %s%s ", label, dim(":"))
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("input error: %v", err)
	}
	s := strings.TrimRight(line, "\r\n")
	if s == "" {
		return def, nil
	}
	return s, nil
}

func copyToClipboard(text string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("clip")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "-b")
		} else {
			return false
		}
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run() == nil
}

// menuPromptFile prompts for a file path, retrying if the file does not exist.
// Returns an error if the user cancels or input fails.
func menuPromptFile(label, def string) (string, error) {
	promptLabel := label
	for {
		path, err := menuPromptStr(promptLabel, def)
		if err != nil {
			return "", err
		}
		if path == "" {
			return "", usagef("input cancelled")
		}
		if path == "q" {
			return "", usagef("input cancelled")
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  %s File not found: %s. Please enter a valid path (or 'q' to cancel):\n", yellow("⚠"), path)
			promptLabel = "Valid path (or 'q' to cancel)"
			def = ""
			continue
		}
		return path, nil
	}
}

// menuEncrypt interactively collects enc parameters and runs the encryption.
func menuEncrypt() error {
	inPath, err := menuPromptFile("Input file", "")
	if err != nil {
		return err
	}
	outPath, err := menuPromptStr("Output file", inPath+".enc")
	if err != nil {
		return err
	}
	if inPath == outPath {
		return usagef("input and output must be different files")
	}
	pass, err := resolvePass("", true)
	if err != nil {
		return err
	}
	defer zero(pass)

	rmStr, err := menuPromptStr("Wipe source file after encryption? (y/n)", "n")
	if err != nil {
		return err
	}
	rm := strings.EqualFold(strings.TrimSpace(rmStr), "y")

	inFi, _ := os.Stat(inPath)
	t0 := time.Now()
	if err := runCrypt(inPath, outPath, pass, true, defaultRounds, rm); err != nil {
		return err
	}
	elapsed := time.Since(t0)
	outFi, _ := os.Stat(outPath)

	fmt.Fprintln(os.Stderr)
	drawCard("ENCRYPTED SUCCESSFULLY", [][2]string{
		{"Input", fmt.Sprintf("%s  (%s)", inPath, fmtSize(inFi.Size()))},
		{"Output", fmt.Sprintf("%s  (%s)", outPath, fmtSize(outFi.Size()))},
		{"Cipher", "AES-256-GCM"},
		{"KDF", fmt.Sprintf("%d rounds PBKDF2-SHA-256", defaultRounds)},
		{"Time", fmtDur(elapsed)},
	}, true)
	return nil
}

// menuDecrypt interactively collects dec parameters and runs the decryption.
func menuDecrypt() error {
	inPath, err := menuPromptFile("Input file", "")
	if err != nil {
		return err
	}
	// Sensible default: strip .enc, or append .dec if there is no .enc suffix.
	defOut := strings.TrimSuffix(inPath, ".enc")
	if defOut == inPath {
		defOut = inPath + ".dec"
	}
	outPath, err := menuPromptStr("Output file", defOut)
	if err != nil {
		return err
	}
	if inPath == outPath {
		return usagef("input and output must be different files")
	}
	pass, err := resolvePass("", false)
	if err != nil {
		return err
	}
	defer zero(pass)

	inFi, _ := os.Stat(inPath)
	t0 := time.Now()
	if err := runCrypt(inPath, outPath, pass, false, 0, false); err != nil {
		return err
	}
	elapsed := time.Since(t0)
	outFi, _ := os.Stat(outPath)

	fmt.Fprintln(os.Stderr)
	drawCard("DECRYPTED SUCCESSFULLY", [][2]string{
		{"Input", fmt.Sprintf("%s  (%s)", inPath, fmtSize(inFi.Size()))},
		{"Output", fmt.Sprintf("%s  (%s)", outPath, fmtSize(outFi.Size()))},
		{"Cipher", "AES-256-GCM  ✔ authenticated"},
		{"Time", fmtDur(elapsed)},
	}, true)
	return nil
}

// menuView interactively views an encrypted file.
func menuView() error {
	inPath, err := menuPromptFile("Input file", "")
	if err != nil {
		return err
	}
	pass, err := resolvePass("", false)
	if err != nil {
		return err
	}
	defer zero(pass)

	src, err := os.Open(inPath)
	if err != nil {
		return usagef("cannot open input: %v", err)
	}
	defer src.Close()

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("--- START ---"))
	if err := decryptStream(bufio.NewReaderSize(src, chunkSize+tagLen), os.Stdout, pass); err != nil {
		fmt.Fprintln(os.Stderr, "")
		return usagef("decrypt failed: %v", err)
	}
	fmt.Fprintln(os.Stderr, dim("\n--- END ---"))
	return nil
}

// menuEdit interactively edits an encrypted file in place.
func menuEdit() error {
	inPath, err := menuPromptFile("Input file", "")
	if err != nil {
		return err
	}
	pass, err := resolvePass("", false)
	if err != nil {
		return err
	}
	defer zero(pass)

	tmp, err := os.CreateTemp("", "bastion-edit-*.txt")
	if err != nil {
		return usagef("cannot create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer wipeFile(tmpPath)

	if err := runCrypt(inPath, tmpPath, pass, false, 0, false); err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad.exe"
		} else {
			editor = "nano"
			if _, err := exec.LookPath("nano"); err != nil {
				editor = "vi"
			}
		}
	}

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return usagef("editor failed: %v", err)
	}

	if err := runCrypt(tmpPath, inPath, pass, true, defaultRounds, false); err != nil {
		return usagef("re-encryption failed: %v", err)
	}
	
	fmt.Fprintln(os.Stderr)
	drawCard("EDITED SUCCESSFULLY", [][2]string{
		{"File", inPath},
		{"Editor", editor},
		{"Status", "Re-encrypted & tmp wiped"},
	}, true)
	return nil
}

// menuWipe interactively shreds a file.
func menuWipe() error {
	path, err := menuPromptFile("File to wipe", "")
	if err != nil {
		return err
	}
	
	confirm, err := menuPromptStr(fmt.Sprintf("Type 'yes' to permanently shred %s", path), "")
	if err != nil {
		return err
	}
	if confirm != "yes" {
		return usagef("wipe aborted")
	}

	t0 := time.Now()
	if err := wipeFile(path); err != nil {
		return usagef("wipe failed: %v", err)
	}
	elapsed := time.Since(t0)

	fmt.Fprintln(os.Stderr)
	drawCard("FILE WIPED", [][2]string{
		{"File", path},
		{"Passes", "Random + Zeroes"},
		{"Time", fmtDur(elapsed)},
	}, true)
	return nil
}

// menuTOTP interactively runs TOTP gen (with live countdown) or verify.
func menuTOTP() error {
	fmt.Fprintln(os.Stderr, "  "+yellow("[A]")+" Generate code with countdown   "+yellow("[B]")+" Verify code")
	fmt.Fprint(os.Stderr, "  Mode [a]: ")
	modeLine, _ := stdin.ReadString('\n')
	mode := strings.TrimRight(modeLine, "\r\n ")

	secret, err := menuPromptStr("Base32 secret", "")
	if err != nil || secret == "" {
		return usagef("base32 secret is required")
	}

	if strings.EqualFold(mode, "b") {
		code, err := menuPromptStr("6-digit code", "")
		if err != nil || code == "" {
			return usagef("code is required")
		}
		ok, err := totpVerify(secret, code, time.Now().Unix())
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr)
		if !ok {
			drawCard("INVALID CODE", [][2]string{{"Code", code}}, false)
			return secf("INVALID code")
		}
		drawCard("CODE VERIFIED", [][2]string{
			{"Code", code},
			{"Window", "±1 time step (30 s)"},
		}, true)
		return nil
	}

	// Generate mode: show a live countdown bar until the window expires.
	return runLiveTOTP(secret)
}

// menuScan interactively collects a directory path and runs the secret scanner.
func menuScan() error {
	dir, err := menuPromptStr("Directory to scan", ".")
	if err != nil {
		return err
	}
	info, statErr := os.Stat(dir)
	if statErr != nil || !info.IsDir() {
		return usagef("not a directory: %s", dir)
	}

	fmt.Fprintln(os.Stderr, "  "+dim("Scanning..."))
	t0 := time.Now()
	total, files, err := scanDir(os.Stdout, dir, 4.5)
	elapsed := time.Since(t0)
	if err != nil {
		return usagef("scan failed: %v", err)
	}

	status := "CLEAN — NO SECRETS FOUND"
	ok := true
	if total > 0 {
		status = fmt.Sprintf("%d POTENTIAL SECRET(S) FOUND", total)
		ok = false
	}
	fmt.Fprintln(os.Stderr)
	drawCard(status, [][2]string{
		{"Directory", dir},
		{"Files", fmt.Sprintf("%d scanned", files)},
		{"Findings", fmt.Sprintf("%d", total)},
		{"Time", fmtDur(elapsed)},
	}, ok)
	if !ok {
		return secf("%d potential secret(s) found", total)
	}
	return nil
}

// menuGen interactively generates a random password.
func menuGen() error {
	var length int
	for {
		lenStr, err := menuPromptStr("Password length", "24")
		if err != nil {
			return err
		}
		if _, e := fmt.Sscanf(lenStr, "%d", &length); e != nil || length < 8 {
			fmt.Fprintln(os.Stderr, "  "+yellow("⚠")+" Length must be at least 8 characters. Please try again:")
			continue
		}
		break
	}
	symStr, err := menuPromptStr("Include symbols? (y/n)", "y")
	if err != nil {
		return err
	}
	symbols := !strings.EqualFold(strings.TrimSpace(symStr), "n")

	t0 := time.Now()
	pw, classes := genPassword(length, symbols)
	elapsed := time.Since(t0)
	pool := strings.Join(classes, "")
	entropy := float64(length) * math.Log2(float64(len(pool)))

	fmt.Fprintln(os.Stderr)
	// Print the password to stdout so it can be piped.
	fmt.Println(green(string(pw)))
	fmt.Fprintln(os.Stderr)

	copied := copyToClipboard(string(pw))
	rows := [][2]string{
		{"Length", fmt.Sprintf("%d chars", length)},
		{"Entropy", fmt.Sprintf("~%.0f bits (pool: %d chars)", entropy, len(pool))},
		{"CSPRNG", "crypto/rand"},
		{"Time", fmtDur(elapsed)},
	}
	if copied {
		rows = append(rows, [2]string{"Clipboard", "📋 Copied to clipboard!"})
	}

	drawCard("PASSWORD GENERATED", rows, true)
	zero(pw)
	return nil
}

// menuHash interactively streams a file through a hash function.
func menuHash() error {
	path, err := menuPromptFile("File path", "")
	if err != nil {
		return err
	}
	algo, err := menuPromptStr("Algorithm (sha256/sha512)", "sha256")
	if err != nil {
		return err
	}

	fi, _ := os.Stat(path)
	t0 := time.Now()
	sum, err := hashFile(path, algo)
	elapsed := time.Since(t0)
	if err != nil {
		return err
	}

	// Print digest to stdout so it is pipeable in non-menu usage.
	fmt.Printf("%s  %s\n", green(sum), path)
	fmt.Fprintln(os.Stderr)

	var sizeRow string
	if fi != nil {
		sizeRow = fmtSize(fi.Size())
	}
	drawCard("DIGEST COMPUTED", [][2]string{
		{"File", path},
		{"Size", sizeRow},
		{"Algorithm", strings.ToUpper(algo)},
		{"Digest", sum[:16] + "…"},
		{"Time", fmtDur(elapsed)},
	}, true)
	return nil
}

// cmdMenu is an interactive REPL menu launched when bastion is run without
// subcommands (or with the explicit "menu" subcommand) in a terminal.
//
// When stdout is not a TTY (automated pipelines, test harnesses) the function
// falls back to the plain usage banner and exits 1, preserving the historic
// behaviour that the test suite relies on.
func cmdMenu() error {
	if !isTTY(os.Stdout) {
		fmt.Fprint(os.Stderr, usageText)
		return errQuiet(exitUsage)
	}

	for {
		drawDashboard()

		line, err := stdin.ReadString('\n')
		if err != nil {
			// EOF (Ctrl+D) — exit the REPL cleanly.
			fmt.Fprintln(os.Stderr)
			return nil
		}
		choice := strings.ToLower(strings.TrimRight(line, "\r\n "))

		// Exit immediately — no card, no pause.
		if choice == "0" || choice == "q" || choice == "quit" || choice == "exit" {
			clearScreen()
			fmt.Fprintln(os.Stderr, dim("  Goodbye."))
			return nil
		}

		// Clear screen before running the selected action.
		clearScreen()
		fmt.Fprintln(os.Stderr)

		var runErr error
		switch choice {
		case "1", "e":
			runErr = menuEncrypt()
		case "2", "d":
			runErr = menuDecrypt()
		case "3", "v":
			runErr = menuView()
		case "4", "m":
			runErr = menuEdit()
		case "5", "w":
			runErr = menuWipe()
		case "6", "t":
			runErr = menuTOTP()
		case "7", "s":
			runErr = menuScan()
		case "8", "g":
			runErr = menuGen()
		case "9", "h":
			runErr = menuHash()
		case "k", "doctor":
			runErr = cmdDoctor(nil)
		case "b", "bench":
			runErr = cmdBench(nil)
		case "?", "help":
			fmt.Fprint(os.Stderr, usageText)
		default:
			warnf("Unknown choice %q — use a number 1–9 or a hotkey (E D V M W T S G H Q K B Q).", choice)
		}

		if runErr != nil {
			// Show error inline; stay in the REPL so the user can retry.
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "  "+red("✘")+"  "+runErr.Error())
		}

		pauseForEnter()
	}
}

// ---------------------------------------------------------------- CLI

// flagErr maps the flag package's outcome onto our exit codes. The flag package
// has already printed the detail, so nothing more is printed. Note that we use
// ContinueOnError rather than ExitOnError: ExitOnError exits with status 2, which
// would make a simple typo look like a security failure.
func flagErr(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return errQuiet(exitOK)
	}
	return errQuiet(exitUsage)
}

func cmdCrypt(args []string, encrypt bool) error {
	name := "enc"
	if !encrypt {
		name = "dec"
	}
	// Pre-parse and strip auto-wipe flags to support flexible positioning
	// (e.g. `bastion enc secret.txt -rm` instead of just `bastion enc -rm secret.txt`)
	var cleanArgs []string
	autoWipe := false
	for _, arg := range args {
		if arg == "-rm" || arg == "--rm" || arg == "-wipe" || arg == "--wipe" {
			autoWipe = true
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}
	args = cleanArgs

	fl := flag.NewFlagSet(name, flag.ContinueOnError)
	in := fl.String("in", "", "input file")
	out := fl.String("out", "", "output file")
	pass := fl.String("pass", "", "passphrase (prompted on stdin if omitted)")
	// Only enc takes -rounds: dec reads the count out of the file it is opening.
	rounds := defaultRounds
	if encrypt {
		fl.IntVar(&rounds, "rounds", defaultRounds,
			fmt.Sprintf("PBKDF2 iterations (%d..%d); stored in the file, so dec needs no flag",
				minRounds, maxRounds))
	}
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	// Resolve positional arguments: named flags always take precedence.
	pos := fl.Args()
	if *in == "" && len(pos) > 0 {
		*in = pos[0]
		pos = pos[1:]
	}
	if *in == "" {
		return usagef("%s requires an input file (-in or first positional argument)", name)
	}
	if *out == "" {
		if len(pos) > 0 {
			*out = pos[0]
		} else if encrypt {
			*out = *in + ".enc"
		} else {
			// dec: strip .enc if present, otherwise append .dec
			stripped := strings.TrimSuffix(*in, ".enc")
			if stripped != *in {
				*out = stripped
			} else {
				*out = *in + ".dec"
			}
		}
	}
	if *in == *out {
		return usagef("-in and -out must be different files")
	}
	if rounds < minRounds || rounds > maxRounds {
		return usagef("-rounds must be between %d and %d, got %d", minRounds, maxRounds, rounds)
	}
	p, err := resolvePass(*pass, encrypt)
	if err != nil {
		return err
	}
	defer zero(p)
	return runCrypt(*in, *out, p, encrypt, rounds, autoWipe)
}

func cmdView(args []string) error {
	fl := flag.NewFlagSet("view", flag.ContinueOnError)
	passFlag := fl.String("pass", "", "passphrase (prompted on stdin if omitted)")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if fl.NArg() == 0 {
		return usagef("view requires a file to decrypt")
	}
	inPath := fl.Arg(0)
	pass, err := resolvePass(*passFlag, false)
	if err != nil {
		return err
	}
	defer zero(pass)

	src, err := os.Open(inPath)
	if err != nil {
		return usagef("cannot open input: %v", err)
	}
	defer src.Close()

	if err := decryptStream(bufio.NewReaderSize(src, chunkSize+tagLen), os.Stdout, pass); err != nil {
		return usagef("decrypt failed: %v", err)
	}
	return nil
}

func cmdEdit(args []string) error {
	fl := flag.NewFlagSet("edit", flag.ContinueOnError)
	passFlag := fl.String("pass", "", "passphrase (prompted on stdin if omitted)")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if fl.NArg() == 0 {
		return usagef("edit requires a file to decrypt")
	}
	inPath := fl.Arg(0)
	pass, err := resolvePass(*passFlag, false)
	if err != nil {
		return err
	}
	defer zero(pass)

	tmp, err := os.CreateTemp("", "bastion-edit-*.txt")
	if err != nil {
		return usagef("cannot create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer wipeFile(tmpPath)

	if err := runCrypt(inPath, tmpPath, pass, false, 0, false); err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad.exe"
		} else {
			editor = "nano"
			if _, err := exec.LookPath("nano"); err != nil {
				editor = "vi"
			}
		}
	}

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return usagef("editor failed: %v", err)
	}

	if err := runCrypt(tmpPath, inPath, pass, true, defaultRounds, false); err != nil {
		return usagef("re-encryption failed: %v", err)
	}
	okf("Successfully edited and re-encrypted %s", inPath)
	return nil
}

func cmdWipe(args []string) error {
	fl := flag.NewFlagSet("wipe", flag.ContinueOnError)
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if fl.NArg() == 0 {
		return usagef("wipe requires a file to shred")
	}
	path := fl.Arg(0)
	if err := wipeFile(path); err != nil {
		return usagef("wipe failed: %v", err)
	}
	okf("Wiped and removed %s", path)
	return nil
}

const usageText = `bastion — zero-dependency security toolbox

USAGE
  bastion                                                    interactive menu (requires a TTY)
  bastion menu                                               same as above
  bastion enc  [<file>] [-in <f>] [-out <f>] [-pass <p>] [-rounds <n>] [-rm]
                                                             encrypt (auto-names to <file>.enc)
  bastion dec  [<file>] [-in <f>] [-out <f>] [-pass <p>]     decrypt (auto-strips .enc suffix)
  bastion view <file.enc>                                    decrypt to stdout
  bastion edit <file.enc>                                    securely edit in place
  bastion wipe <file>                                        cryptographic file shredder
  bastion totp gen    [<secret>] [-secret <b32>]             generate a 6-digit TOTP code
  bastion totp verify [<secret>] [<code>] [-secret] [-code]  verify a code (±1 step drift)
  bastion scan [<dir>] [-dir <path>] [-entropy <float>]      hunt for leaked secrets (default: .)
  bastion gen  [-len <int>] [-symbols]                       generate a strong password
  bastion hash [<file>] [-file <path>] [-algo sha256|sha512] stream-hash a file
  bastion doctor                                             run cryptographic self-diagnostics (KAT)
  bastion bench                                              run live hardware performance benchmarks

EXIT CODES
  0  success        1  bad arguments or I/O error        2  tamper / secret found
`

// dispatch runs one command line and returns an error carrying its exit code.
// main is the only place that calls os.Exit, which keeps all of this testable.
func dispatch(args []string) error {
	if len(args) == 0 {
		// No subcommand: launch the interactive menu when stdout is a TTY,
		// otherwise fall back to the usage banner (preserves historic exit-1
		// behaviour for scripts and the automated test suite).
		return cmdMenu()
	}
	switch args[0] {
	case "menu":
		return cmdMenu()
	case "enc":
		return cmdCrypt(args[1:], true)
	case "dec":
		return cmdCrypt(args[1:], false)
	case "view":
		return cmdView(args[1:])
	case "edit":
		return cmdEdit(args[1:])
	case "wipe":
		return cmdWipe(args[1:])
	case "totp":
		if len(args) < 2 {
			return usagef("totp requires a subcommand: gen or verify")
		}
		switch args[1] {
		case "gen":
			return cmdTOTPGen(args[2:])
		case "verify":
			return cmdTOTPVerify(args[2:])
		default:
			return cmdTOTPGen(args[1:])
		}
	case "scan":
		return cmdScan(args[1:])
	case "gen":
		return cmdGen(args[1:])
	case "hash":
		return cmdHash(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "bench":
		return cmdBench(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, usageText)
		return nil
	}
	return usagef("unknown command %q — run `bastion help`", args[0])
}

func main() {
	err := dispatch(os.Args[1:])
	if err == nil {
		return
	}
	if msg := err.Error(); msg != "" {
		fmt.Fprintln(os.Stderr, red("✘ ")+msg)
	}
	code := exitUsage
	var e exitErr
	if errors.As(err, &e) {
		code = e.code
	}
	os.Exit(code)
}