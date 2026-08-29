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

// runCrypt wires files to the streaming core, removing the output on any failure.
func runCrypt(inPath, outPath string, pass []byte, encrypt bool, rounds int) error {
	defer zero(pass)

	src, err := os.Open(inPath)
	if err != nil {
		return usagef("cannot open input: %v", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
		os.Remove(outPath) // fail closed: never leave partial output behind
		var e exitErr
		if errors.As(err, &e) {
			return err
		}
		return usagef("%v", err)
	}

	fi, _ := os.Stat(outPath)
	if encrypt {
		okf("Encrypted %s → %s (%d bytes, %d PBKDF2 rounds)", inPath, outPath, fi.Size(), rounds)
	} else {
		okf("Decrypted %s → %s (%d bytes)", inPath, outPath, fi.Size())
	}
	return nil
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
	secret := fl.String("secret", "", "base32-encoded shared secret (required)")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if *secret == "" {
		return usagef("totp gen requires -secret")
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
	secret := fl.String("secret", "", "base32-encoded shared secret (required)")
	code := fl.String("code", "", "6-digit code to check (required)")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if *secret == "" || *code == "" {
		return usagef("totp verify requires -secret and -code")
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
	".git": true, "node_modules": true, "vendor": true, "dist": true,
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
	dir := fl.String("dir", ".", "directory to scan recursively")
	threshold := fl.Float64("entropy", 4.5, "Shannon entropy threshold in bits per character")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
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
	path := fl.String("file", "", "file to hash (required)")
	algo := fl.String("algo", "sha256", "sha256 or sha512")
	if err := fl.Parse(args); err != nil {
		return flagErr(err)
	}
	if *path == "" {
		return usagef("hash requires -file")
	}

	sum, err := hashFile(*path, *algo)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", green(sum), *path)
	return nil
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
	fl := flag.NewFlagSet(name, flag.ContinueOnError)
	in := fl.String("in", "", "input file (required)")
	out := fl.String("out", "", "output file (required)")
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

	if *in == "" || *out == "" {
		return usagef("%s requires -in and -out", name)
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
	return runCrypt(*in, *out, p, encrypt, rounds)
}

const usageText = `bastion — zero-dependency security toolbox

USAGE
  bastion enc  -in <file> -out <file> [-pass <pass>] [-rounds <n>]
                                                         encrypt a file (AES-256-GCM)
  bastion dec  -in <file> -out <file> [-pass <pass>]     decrypt a file (exit 2 if tampered)
  bastion totp gen    -secret <base32>                   generate a 6-digit TOTP code
  bastion totp verify -secret <base32> -code <code>      verify a code (±1 step drift)
  bastion scan -dir <path> [-entropy <float>]            hunt for leaked secrets
  bastion gen  [-len <int>] [-symbols]                   generate a strong password
  bastion hash -file <file> [-algo sha256|sha512]        stream-hash a file

EXIT CODES
  0  success        1  bad arguments or I/O error        2  tamper / secret found
`

// dispatch runs one command line and returns an error carrying its exit code.
// main is the only place that calls os.Exit, which keeps all of this testable.
func dispatch(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return errQuiet(exitUsage)
	}
	switch args[0] {
	case "enc":
		return cmdCrypt(args[1:], true)
	case "dec":
		return cmdCrypt(args[1:], false)
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
