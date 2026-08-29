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

func cmdTOTPGen(args []string) error {
	fl := flag.NewFlagSet("totp gen", flag.ContinueOnError)
	secret := fl.String("secret", "", "base32-encoded shared secret")
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

	now := time.Now().Unix()
	code, err := totpAt(*secret, now)
	if err != nil {
		return err
	}
	left := totpStep - now%totpStep

	fmt.Println(green(code)) // stdout: just the code, so it pipes cleanly
	notef("valid for %ds", left)
	if left <= 5 {
		warnf("this code expires in %ds — wait for the next one if you are cutting it close", left)
	}
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

// ---------------------------------------------------------------- interactive TUI menu

// menuHeader is the styled banner shown at the top of every menu screen.
const menuHeader = "\n" +
	"╭──────────────────────────────────────────────────────╮\n" +
	"│   BASTION  —  Zero-Dependency Security Toolbox    │\n" +
	"│   ┃ AES-256-GCM ┃ PBKDF2-SHA-256 ┃ CSPRNG ┃         │\n" +
	"╰──────────────────────────────────────────────────────╯"

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
	fmt.Fprint(os.Stderr, "\n  "+dim("Press [Enter] to return to menu..."))
	stdin.ReadString('\n') //nolint:errcheck
	fmt.Fprintln(os.Stderr)
}

// menuPromptStr displays a labelled input prompt with an optional default value
// and reads one line from stdin, returning the default when the user hits Enter.
func menuPromptStr(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(os.Stderr, "  %s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "  %s: ", label)
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

// menuEncrypt interactively collects enc parameters and runs the encryption.
func menuEncrypt() error {
	inPath, err := menuPromptStr("Input file", "")
	if err != nil || inPath == "" {
		return usagef("input file is required")
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
	inPath, err := menuPromptStr("Input file", "")
	if err != nil || inPath == "" {
		return usagef("input file is required")
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
	inPath, err := menuPromptStr("Input file", "")
	if err != nil || inPath == "" {
		return usagef("input file is required")
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
	inPath, err := menuPromptStr("Input file", "")
	if err != nil || inPath == "" {
		return usagef("input file is required")
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
	path, err := menuPromptStr("File to wipe", "")
	if err != nil || path == "" {
		return usagef("file path is required")
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
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+dim("Live countdown — auto-exits when the 30s window rolls over"))
	fmt.Fprintln(os.Stderr)

	const barCells = 24
	for {
		now := time.Now().Unix()
		secsLeft := totpStep - now%totpStep
		code, err := totpAt(secret, now)
		if err != nil {
			fmt.Fprintln(os.Stderr)
			return err
		}

		filled := int(secsLeft * barCells / totpStep)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barCells-filled)

		var urgency string
		if secsLeft <= 5 {
			urgency = red(fmt.Sprintf("%2ds left", secsLeft))
		} else {
			urgency = dim(fmt.Sprintf("%2ds left", secsLeft))
		}
		fmt.Fprintf(os.Stderr, "\r  %s  [%s]  %s   ",
			green(code), bar, urgency)

		time.Sleep(time.Second)

		if secsLeft <= 1 {
			// Window just expired — break out so the card can show the final code.
			break
		}
	}
	fmt.Fprintln(os.Stderr) // end the \r line
	return nil
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
	lenStr, err := menuPromptStr("Password length", "24")
	if err != nil {
		return err
	}
	var length int
	if _, e := fmt.Sscanf(lenStr, "%d", &length); e != nil || length < 8 {
		return usagef("invalid length %q (minimum 8)", lenStr)
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
	drawCard("PASSWORD GENERATED", [][2]string{
		{"Length", fmt.Sprintf("%d chars", length)},
		{"Entropy", fmt.Sprintf("~%.0f bits (pool: %d chars)", entropy, len(pool))},
		{"CSPRNG", "crypto/rand"},
		{"Time", fmtDur(elapsed)},
	}, true)
	zero(pw)
	return nil
}

// menuHash interactively streams a file through a hash function.
func menuHash() error {
	path, err := menuPromptStr("File path", "")
	if err != nil || path == "" {
		return usagef("file path is required")
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

	menuItems := []string{
		"  " + yellow("[E]") + "ncrypt File          " + dim("AES-256-GCM + PBKDF2"),
		"  " + yellow("[D]") + "ecrypt File          " + dim("authenticated decryption"),
		"  " + yellow("[V]") + "iew Encrypted File   " + dim("decrypt to stdout"),
		"  " + yellow("[I]") + "n-Place Edit         " + dim("secure temporary editor"),
		"  " + yellow("[W]") + "ipe File             " + dim("cryptographic shredder"),
		"  " + yellow("[T]") + "OTP Authenticator    " + dim("RFC 6238 · live countdown"),
		"  " + yellow("[S]") + "can for Secrets      " + dim("entropy + pattern matching"),
		"  " + yellow("[G]") + "enerate Password     " + dim("CSPRNG · zero bias"),
		"  " + yellow("[H]") + "ash File             " + dim("SHA-256 / SHA-512"),
		"  " + yellow("[?]") + " CLI Help Reference",
		"  " + yellow("[Q]") + "uit",
	}

	for {
		clearScreen()
		fmt.Fprintln(os.Stderr, green(menuHeader))
		fmt.Fprintln(os.Stderr)
		for _, item := range menuItems {
			fmt.Fprintln(os.Stderr, item)
		}
		fmt.Fprint(os.Stderr, "\n  Choice: ")

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
		case "4", "i":
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
		case "10", "?":
			fmt.Fprint(os.Stderr, usageText)
		default:
			warnf("Unknown choice %q — use a number 1–10 or a hotkey (E D V I W T S G H Q).", choice)
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
		}
		return usagef("unknown totp subcommand %q (use gen or verify)", args[1])
	case "scan":
		return cmdScan(args[1:])
	case "gen":
		return cmdGen(args[1:])
	case "hash":
		return cmdHash(args[1:])
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
