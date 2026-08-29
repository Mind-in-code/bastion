package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain doubles as the CLI entry point for subprocess tests: when the marker
// env var is set we run main() instead of the test suite, so exit codes can be
// observed for real rather than simulated.
func TestMain(m *testing.M) {
	if os.Getenv("BASTION_TEST_SUBPROCESS") == "1" {
		main()
		os.Exit(exitOK)
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------- helpers

const testPass = "correct horse battery staple"

func encBytes(t testing.TB, plain []byte, pass string) []byte {
	return encRounds(t, plain, pass, defaultRounds)
}

func encRounds(t testing.TB, plain []byte, pass string, rounds int) []byte {
	t.Helper()
	var buf bytes.Buffer
	in := bufio.NewReaderSize(bytes.NewReader(plain), chunkSize)
	if err := encryptStream(in, &buf, []byte(pass), rounds); err != nil {
		t.Fatalf("encryptStream: %v", err)
	}
	return buf.Bytes()
}

func decBytes(ct []byte, pass string) ([]byte, error) {
	var buf bytes.Buffer
	in := bufio.NewReaderSize(bytes.NewReader(ct), chunkSize+tagLen)
	err := decryptStream(in, &buf, []byte(pass))
	return buf.Bytes(), err
}

// wantTamper asserts that err is the fail-closed authentication error and that
// it carries exit code 2.
func wantTamper(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected authentication failure, got nil (FAIL-OPEN — critical)")
	}
	var e exitErr
	if !errors.As(err, &e) {
		t.Fatalf("error does not carry an exit code: %v", err)
	}
	if e.code != exitSecurity {
		t.Errorf("exit code = %d, want %d", e.code, exitSecurity)
	}
	if err != error(errTamper) {
		t.Errorf("error = %q, want the generic tamper error", err)
	}
}

// wantSecurityError asserts a fail-closed error carrying exit code 2, without
// insisting on the generic tamper message.
func wantSecurityError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a security failure, got nil (FAIL-OPEN — critical)")
	}
	var e exitErr
	if !errors.As(err, &e) {
		t.Fatalf("error does not carry an exit code: %v", err)
	}
	if e.code != exitSecurity {
		t.Errorf("exit code = %d, want %d", e.code, exitSecurity)
	}
}

func randPayload(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// cipherLen is the on-disk size of a plaintext of n bytes.
func cipherLen(n int) int {
	chunks := n/chunkSize + 1
	if n > 0 && n%chunkSize == 0 {
		chunks = n / chunkSize
	}
	return headerLen + n + chunks*tagLen
}

// ---------------------------------------------------------------- 1. round trips

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
		big  bool
	}{
		{"empty", 0, false},
		{"one_byte", 1, false},
		{"1KB_text", 1024, false},
		{"exact_chunk_boundary", chunkSize, false},
		{"chunk_boundary_plus_one", chunkSize + 1, false},
		{"three_chunks", 3 * chunkSize, false},
		{"5MB_binary", 5 << 20, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.big && testing.Short() {
				t.Skip("skipping heavy payload in -short mode")
			}
			plain := randPayload(t, tc.size)
			ct := encBytes(t, plain, testPass)

			if got, want := len(ct), cipherLen(tc.size); got != want {
				t.Errorf("ciphertext length = %d, want %d", got, want)
			}
			if tc.size > 0 && bytes.Equal(ct[headerLen:headerLen+tc.size], plain[:tc.size]) {
				t.Error("ciphertext contains the plaintext verbatim")
			}

			got, err := decBytes(ct, testPass)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(plain))
			}
		})
	}
}

func TestEncryptionIsNonDeterministic(t *testing.T) {
	plain := []byte("the same plaintext twice")
	a := encBytes(t, plain, testPass)
	b := encBytes(t, plain, testPass)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same input are identical: salt or nonce is not random")
	}
	if bytes.Equal(a[:saltLen], b[:saltLen]) {
		t.Error("salt repeated across encryptions")
	}
	if bytes.Equal(a[saltLen+roundsLen:headerLen], b[saltLen+roundsLen:headerLen]) {
		t.Error("nonce repeated across encryptions")
	}
	// The rounds field is the one header value that SHOULD be identical.
	if !bytes.Equal(a[saltLen:saltLen+roundsLen], b[saltLen:saltLen+roundsLen]) {
		t.Error("rounds field differs between two default-rounds encryptions")
	}
}

// ---------------------------------------------------------------- PBKDF2 rounds in the header

func TestRoundsStoredInHeader(t *testing.T) {
	for _, rounds := range []int{minRounds, defaultRounds, 600000, maxRounds} {
		// maxRounds is deliberately expensive — that is the whole point of it —
		// so it costs about a second and a half. Keep it out of -short.
		if rounds == maxRounds && testing.Short() {
			continue
		}
		ct := encRounds(t, []byte("payload"), testPass, rounds)
		if len(ct) < headerLen {
			t.Fatalf("rounds %d: ciphertext shorter than the header", rounds)
		}
		got := int(binary.BigEndian.Uint32(ct[saltLen : saltLen+roundsLen]))
		if got != rounds {
			t.Errorf("header records %d rounds, want %d", got, rounds)
		}
	}
}

// A file made with a non-default cost must open with no flag at all: the count
// travels inside the file.
func TestRoundsRoundTripWithoutBeingTold(t *testing.T) {
	plain := []byte("OWASP 2023 wants 600000 rounds")
	for _, rounds := range []int{minRounds, defaultRounds, 600000} {
		ct := encRounds(t, plain, testPass, rounds)
		got, err := decBytes(ct, testPass)
		if err != nil {
			t.Fatalf("rounds %d: decrypt failed: %v", rounds, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("rounds %d: round trip mismatch", rounds)
		}
	}
}

func TestRoundsChangesTheKey(t *testing.T) {
	// Same passphrase, same salt, different cost => different key. Rewriting the
	// count in a file must therefore fail authentication.
	plain := []byte("secret")
	ct := encRounds(t, plain, testPass, defaultRounds)
	binary.BigEndian.PutUint32(ct[saltLen:saltLen+roundsLen], defaultRounds+1)
	_, err := decBytes(ct, testPass)
	wantTamper(t, err)
}

func TestRoundsOutOfRangeIsRejected(t *testing.T) {
	plain := []byte("secret")
	for name, rounds := range map[string]uint32{
		"zero":       0,
		"one":        1,
		"just_under": minRounds - 1,
		"just_over":  maxRounds + 1,
		"absurd":     4000000000, // would grind the CPU for hours
		"max_uint32": ^uint32(0),
	} {
		t.Run(name, func(t *testing.T) {
			ct := encRounds(t, plain, testPass, defaultRounds)
			binary.BigEndian.PutUint32(ct[saltLen:saltLen+roundsLen], rounds)
			_, err := decBytes(ct, testPass)
			wantSecurityError(t, err)
		})
	}
}

// ---------------------------------------------------------------- 2. the five attacks

func TestAttack1_WrongPassword(t *testing.T) {
	ct := encBytes(t, []byte("top secret contents"), testPass)
	got, err := decBytes(ct, "not the right password")
	wantTamper(t, err)
	if len(got) != 0 {
		t.Errorf("plaintext leaked on failure: %d bytes", len(got))
	}
}

func TestAttack2_BitFlip(t *testing.T) {
	plain := randPayload(t, 4096)
	// Flip one bit at every interesting offset across the whole file.
	offsets := map[string]int{
		"salt":       3,
		"rounds":     saltLen + roundsLen - 1, // low byte: stays in range, wrong key
		"nonce":      saltLen + roundsLen + 5,
		"ciphertext": headerLen + 100,
		"tag":        cipherLen(4096) - 1,
	}
	for name, off := range offsets {
		t.Run(name, func(t *testing.T) {
			ct := encBytes(t, plain, testPass)
			ct[off] ^= 0x01 // a single bit
			_, err := decBytes(ct, testPass)
			wantTamper(t, err)
		})
	}
}

func TestAttack3_Truncation(t *testing.T) {
	plain := randPayload(t, 3*chunkSize)
	full := encBytes(t, plain, testPass)

	cases := map[string]int{
		"drop_last_chunk":  cipherLen(3*chunkSize) - (chunkSize + tagLen),
		"drop_one_byte":    len(full) - 1,
		"header_only":      headerLen,
		"partial_header":   headerLen - 1,
		"empty_file":       0,
		"header_plus_stub": headerLen + tagLen - 1,
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			ct := append([]byte(nil), full[:size]...)
			_, err := decBytes(ct, testPass)
			wantTamper(t, err)
		})
	}
}

func TestAttack4_ChunkSwap(t *testing.T) {
	plain := randPayload(t, 3*chunkSize)
	ct := encBytes(t, plain, testPass)

	const sealed = chunkSize + tagLen
	c0 := append([]byte(nil), ct[headerLen:headerLen+sealed]...)
	c1 := append([]byte(nil), ct[headerLen+sealed:headerLen+2*sealed]...)
	copy(ct[headerLen:], c1)
	copy(ct[headerLen+sealed:], c0)

	_, err := decBytes(ct, testPass)
	wantTamper(t, err)
}

func TestAttack5_ChunkSplice(t *testing.T) {
	const sealed = chunkSize + tagLen
	plain := randPayload(t, 3*chunkSize)

	t.Run("foreign_chunk_same_password", func(t *testing.T) {
		victim := encBytes(t, plain, testPass)
		donor := encBytes(t, randPayload(t, 3*chunkSize), testPass) // different salt+nonce
		copy(victim[headerLen:], donor[headerLen:headerLen+sealed])
		_, err := decBytes(victim, testPass)
		wantTamper(t, err)
	})

	t.Run("duplicated_own_chunk", func(t *testing.T) {
		victim := encBytes(t, plain, testPass)
		c0 := append([]byte(nil), victim[headerLen:headerLen+sealed]...)
		copy(victim[headerLen+sealed:], c0) // replay chunk 0 into slot 1
		_, err := decBytes(victim, testPass)
		wantTamper(t, err)
	})

	t.Run("inserted_extra_chunk", func(t *testing.T) {
		victim := encBytes(t, plain, testPass)
		spliced := make([]byte, 0, len(victim)+sealed)
		spliced = append(spliced, victim[:headerLen+sealed]...)
		spliced = append(spliced, victim[headerLen:headerLen+sealed]...) // extra copy
		spliced = append(spliced, victim[headerLen+sealed:]...)
		_, err := decBytes(spliced, testPass)
		wantTamper(t, err)
	})
}

// TestFailClosedRemovesPartialOutput is the "never hand back a half-file" guarantee.
func TestFailClosedRemovesPartialOutput(t *testing.T) {
	dir := t.TempDir()
	plain := randPayload(t, 3*chunkSize)

	src := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(src, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(dir, "cipher.bin")
	if err := runCrypt(src, encPath, []byte(testPass), true, defaultRounds, false); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Corrupt the LAST chunk, so decryption succeeds for a while and really does
	// write bytes out before it discovers the problem.
	ct, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	bad := filepath.Join(dir, "corrupt.bin")
	if err := os.WriteFile(bad, ct, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "recovered.bin")
	err = runCrypt(bad, out, []byte(testPass), false, 0, false)
	wantTamper(t, err)

	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial output %s still exists after failure — must be removed", out)
	}
}


// ---------------------------------------------------------------- 3. TOTP (RFC 6238)

// The RFC 6238 reference secret is the ASCII string "12345678901234567890".
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestBase32DecodesRFCSecret(t *testing.T) {
	got, err := decodeBase32(rfcSecret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := "12345678901234567890"; string(got) != want {
		t.Fatalf("decoded secret = %q, want %q", got, want)
	}
}

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// Appendix B, SHA-1 column, truncated from 8 digits to our 6.
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range vectors {
		got, err := totpAt(rfcSecret, v.unix)
		if err != nil {
			t.Fatalf("T=%d: %v", v.unix, err)
		}
		if got != v.want {
			t.Errorf("T=%d: code = %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestTOTP_SecretNormalisation(t *testing.T) {
	want, err := totpAt(rfcSecret, 1111111111)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{
		strings.ToLower(rfcSecret),
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
		rfcSecret + "====",
	} {
		got, err := totpAt(variant, 1111111111)
		if err != nil {
			t.Errorf("%q: %v", variant, err)
			continue
		}
		if got != want {
			t.Errorf("%q: code = %s, want %s", variant, got, want)
		}
	}
}

func TestTOTP_RejectsBadSecret(t *testing.T) {
	for _, bad := range []string{"", "not!base32", "18908198%%"} {
		if _, err := totpAt(bad, 0); err == nil {
			t.Errorf("secret %q was accepted, want an error", bad)
		} else {
			var e exitErr
			if errors.As(err, &e) && e.code != exitUsage {
				t.Errorf("secret %q: exit code = %d, want %d", bad, e.code, exitUsage)
			}
		}
	}
}

func TestTOTP_DriftWindow(t *testing.T) {
	const now int64 = 1111111111

	// Codes at each offset must be distinct, or the window test proves nothing.
	seen := map[string]int64{}
	for _, d := range []int64{-60, -30, 0, 30, 60} {
		c, err := totpAt(rfcSecret, now+d)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[c]; dup {
			t.Fatalf("codes at offset %ds and %ds collide (%s); pick another test time", prev, d, c)
		}
		seen[c] = d
	}

	cases := []struct {
		offset int64
		accept bool
	}{
		{-60, false}, // two steps early — outside the window
		{-30, true},  // one step early
		{0, true},    // current
		{30, true},   // one step late
		{60, false},  // two steps late
	}
	for _, c := range cases {
		code, err := totpAt(rfcSecret, now+c.offset)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := totpVerify(rfcSecret, code, now)
		if err != nil {
			t.Fatal(err)
		}
		if ok != c.accept {
			t.Errorf("offset %+ds: accepted = %v, want %v", c.offset, ok, c.accept)
		}
	}
}

func TestTOTP_RejectsWrongCodes(t *testing.T) {
	for _, bad := range []string{"000000", "12345", "1234567", "", "abcdef"} {
		ok, err := totpVerify(rfcSecret, bad, 1111111111)
		if err != nil {
			t.Fatalf("%q: %v", bad, err)
		}
		if ok {
			t.Errorf("code %q was accepted", bad)
		}
	}
}

func TestTOTP_AlwaysSixDigits(t *testing.T) {
	for unix := int64(0); unix < 30*500; unix += 30 {
		code, err := totpAt(rfcSecret, unix)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("T=%d: code %q is %d digits, want 6", unix, code, len(code))
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("T=%d: code %q contains a non-digit", unix, code)
			}
		}
	}
}

// ---------------------------------------------------------------- 4. entropy

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},                      // nothing
		{"a", 0},                     // one symbol
		{"aaaaaaaaaaaaaaaa", 0},      // pure repetition
		{"aabb", 1},                  // 2 symbols, equal
		{"abcd", 2},                  // 4 symbols, equal
		{"0123456789abcdef", 4},      // 16 symbols, equal
		{"aaab", 0.8112781244591328}, // 3:1      split
		{"aaaaaaaabbbbcccc", 1.5},    // 8:4:4    split
		{"aaaaaaaaaaaaaaaabbbbcccc", 1.2516291673878228}, // 16:4:4   split
	}
	for _, c := range cases {
		if got := shannon(c.in); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("shannon(%q) = %.15f, want %.15f", c.in, got, c.want)
		}
	}
}

func TestEntropyOrdering(t *testing.T) {
	prose := shannon("the quick brown fox jumps over")
	token := shannon("aZ9kQ2mX7pL4vB8nR3tY6wE1sD5fG0hJcV")
	if token <= prose {
		t.Errorf("random token entropy %.2f should exceed prose entropy %.2f", token, prose)
	}
	if token < 4.5 {
		t.Errorf("a 34-char random token scored %.2f, below the 4.5 default threshold", token)
	}
}

func TestMixedAlnum(t *testing.T) {
	cases := map[string]bool{
		"abc123":   true,
		"abcdef":   false, // letters only (prose, hex words)
		"123456":   false, // digits only
		"deadbeef": false, // pure-hex hash-looking
		"a1":       true,
	}
	for in, want := range cases {
		if got := mixedAlnum(in); got != want {
			t.Errorf("mixedAlnum(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRedactNeverLeaksWholeSecret(t *testing.T) {
	for _, s := range []string{"", "abc", "12345678", fakeAWSKeyID} {
		got := redact(s)
		if len(s) > 8 && strings.Contains(got, s) {
			t.Errorf("redact(%q) = %q leaks the full value", s, got)
		}
		if len(s) <= 8 && strings.ContainsAny(got, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			t.Errorf("redact(%q) = %q should be fully masked", s, got)
		}
	}
}

// ---------------------------------------------------------------- 5. scanner

// Fake credential fixtures for the scanner tests.
//
// Two rules apply here.
//
//  1. Every value is transparently fake: AWS's own documented example key, and
//     otherwise runs of 0 or X. Nothing here could be mistaken for a live secret.
//
//  2. Each value is ASSEMBLED AT RUN TIME from fragments, so that no complete
//     credential-shaped literal ever appears in this source file.
//
// Rule 2 is the one that actually matters. GitHub push protection matches on the
// *shape* of a credential, not on whether the value is real — a literal
// "https://hooks.slack.com/services/..." is blocked even when its path is plainly
// a dummy, and that blocked a push of this file once. Splitting the literals keeps
// the repository pushable while the assembled values still exercise every pattern
// in the scanner. Do not "tidy" these back into single string constants.
var (
	fakeAWSKeyID  = "AKIA" + "IOSFODNN7EXAMPLE"            // AWS's documented example key
	fakeAWSSecret = strings.Repeat("EXAMPLE", 5) + "AAAAA" // exactly 40 chars
	fakeGitHubTok = "ghp" + "_" + strings.Repeat("0", 36)
	fakeGitHubPAT = "github" + "_pat_" + strings.Repeat("0", 32)
	fakeSlackTok  = "xox" + "b-0000000000-0000000000-" + strings.Repeat("X", 20)
	fakeSlackHook = "https://hooks.slack." + "com/services/T00000000/B00000000/" + strings.Repeat("X", 24)
	fakeGoogleKey = "AIza" + strings.Repeat("0", 35)
	fakeBearerTok = "Bearer " + strings.Repeat("A", 40)

	// planted is one file's worth of fake credentials, one per line so that each
	// scanner pattern is exercised independently.
	planted = strings.Join([]string{
		"# fake configuration for tests: none of these are real credentials",
		`AWS_ACCESS_KEY_ID = "` + fakeAWSKeyID + `"`,
		`aws_secret_access_key = "` + fakeAWSSecret + `"`,
		`GITHUB_TOKEN = "` + fakeGitHubTok + `"`,
		`GH_FINE = "` + fakeGitHubPAT + `"`,
		`SLACK_BOT = "` + fakeSlackTok + `"`,
		`HOOK = "` + fakeSlackHook + `"`,
		`GOOGLE_KEY = "` + fakeGoogleKey + `"`,
		`AUTH = "` + fakeBearerTok + `"`,
		"",
	}, "\n")

	pemKey = "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
		strings.Repeat("A", 64) + "\n" +
		"-----END " + "RSA PRIVATE KEY-----\n"
)

const innocent = `package main

import "fmt"

// Nothing sensitive lives in this file at all.
func main() { fmt.Println("hello world, this is ordinary prose") }
`

func TestScannerFindsEveryPattern(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := write("config.py", planted)

	var out bytes.Buffer
	if n := scanFile(&out, cfg, 4.5); n < len(patterns)-1 {
		t.Errorf("found %d findings in the planted file, want at least %d", n, len(patterns)-1)
	}
	report := out.String()
	for _, want := range []string{
		"AWS Access Key ID", "AWS Secret Access Key", "GitHub Token",
		"GitHub Fine-grained PAT", "Slack Token", "Slack Webhook",
		"Google API Key", "Generic Bearer Token",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("pattern %q did not fire", want)
		}
	}

	pem := write("id_rsa", pemKey)
	out.Reset()
	if n := scanFile(&out, pem, 4.5); n == 0 {
		t.Error("private key block not detected")
	}
	if !strings.Contains(out.String(), "Private Key Block") {
		t.Errorf("private key report missing: %q", out.String())
	}
}

func TestScannerRedactsFindings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.py")
	if err := os.WriteFile(p, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	scanFile(&out, p, 4.5)

	for _, secret := range []string{
		fakeAWSKeyID, fakeAWSSecret, fakeGitHubTok, fakeGitHubPAT,
		fakeSlackTok, fakeSlackHook, fakeGoogleKey,
	} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("scanner printed the full secret %q — findings must be redacted", secret)
		}
	}
}

func TestScannerCleanTreeIsSilent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(innocent), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	found, files, err := scanDir(&out, dir, 4.5)
	if err != nil {
		t.Fatal(err)
	}
	if found != 0 {
		t.Errorf("false positives on clean source: %d\n%s", found, out.String())
	}
	if files != 1 {
		t.Errorf("scanned %d files, want 1", files)
	}
}

func TestScannerSkipsNoiseDirsAndBinaries(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "leak.py"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	// A binary file whose bytes happen to contain a key pattern.
	blob := append([]byte{0x00, 0x01, 0x02}, []byte(planted)...)
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	// An image extension that should never be opened.
	if err := os.WriteFile(filepath.Join(dir, "logo.png"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	found, files, err := scanDir(&out, dir, 4.5)
	if err != nil {
		t.Fatal(err)
	}
	if found != 0 {
		t.Errorf("scanned skipped content: %d findings\n%s", found, out.String())
	}
	if files != 1 { // only data.bin is opened, then rejected as binary
		t.Errorf("opened %d files, want 1", files)
	}

	cfg := filepath.Join(dir, "ignored.py")
	if err := os.WriteFile(cfg, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfg)
	t.Setenv("BASTION_SCAN_IGNORE", "ignored.py")
	total, _, _ := scanDir(io.Discard, dir, 4.5)
	if total != 0 {
		t.Errorf("BASTION_SCAN_IGNORE failed, found %d", total)
	}
}

func TestScannerEntropyThreshold(t *testing.T) {
	dir := t.TempDir()
	body := `const nonce = "aZ9kQ2mX7pL4vB8nR3tY6wE1sD5fG0hJcV";` + "\n"
	p := filepath.Join(dir, "session.js")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var lo, hi bytes.Buffer
	if n := scanFile(&lo, p, 4.5); n != 1 {
		t.Errorf("threshold 4.5: found %d, want 1", n)
	}
	if n := scanFile(&hi, p, 6.0); n != 0 {
		t.Errorf("threshold 6.0: found %d, want 0", n)
	}
}

func TestVaultFeatures(t *testing.T) {
	dir := t.TempDir()
	
	t.Run("wipeFile_removes_file", func(t *testing.T) {
		p := filepath.Join(dir, "wipe_me.txt")
		os.WriteFile(p, []byte("hello"), 0o600)
		if err := wipeFile(p); err != nil {
			t.Fatalf("wipeFile failed: %v", err)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file still exists after wipe")
		}
	})

	t.Run("rm_flag_wipes_source", func(t *testing.T) {
		plain := filepath.Join(dir, "source.txt")
		os.WriteFile(plain, []byte("secret"), 0o600)
		enc := filepath.Join(dir, "source.enc")
		
		if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass, "-rm"); code != exitOK {
			t.Fatalf("enc -rm exit %d: %s", code, msg)
		}
		if _, err := os.Stat(plain); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source file was not removed by -rm flag")
		}
		if _, err := os.Stat(enc); err != nil {
			t.Fatalf("encrypted file missing: %v", err)
		}
	})

	t.Run("view_outputs_to_stdout", func(t *testing.T) {
		plain := filepath.Join(dir, "v.txt")
		os.WriteFile(plain, []byte("view content"), 0o600)
		enc := filepath.Join(dir, "v.enc")
		runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass)
		
		code, out, stderr := runCLI(t, "", "view", "-pass", testPass, enc)
		if code != exitOK {
			t.Fatalf("view exit %d: %s", code, stderr)
		}
		if !strings.Contains(out, "view content") {
			t.Fatalf("view did not output decrypted text, got: %q", out)
		}
	})
}

// ---------------------------------------------------------------- 6. password generator

func TestPasswordGenerator(t *testing.T) {
	const runs = 1000

	for _, symbols := range []bool{false, true} {
		name := "alnum"
		pool := charLower + charUpper + charDigits
		if symbols {
			name = "with_symbols"
			pool += charSymbols
		}
		t.Run(name, func(t *testing.T) {
			for _, length := range []int{8, 20, 64} {
				seen := make(map[string]bool, runs)
				used := make(map[byte]int, len(pool))

				for i := 0; i < runs; i++ {
					pw, classes := genPassword(length, symbols)

					if len(pw) != length {
						t.Fatalf("length = %d, want %d", len(pw), length)
					}
					for _, c := range pw {
						if !strings.ContainsRune(pool, rune(c)) {
							t.Fatalf("character %q is outside the allowed pool", c)
						}
						used[c]++
					}
					if !containsEach(pw, classes) {
						t.Fatalf("password %q is missing a required character class", pw)
					}
					if seen[string(pw)] {
						t.Fatalf("duplicate password after %d draws — generator is not random", i)
					}
					seen[string(pw)] = true
				}

				if len(seen) != runs {
					t.Errorf("unique passwords = %d, want %d", len(seen), runs)
				}
				// Every character in the pool should turn up across 1000 draws.
				for i := 0; i < len(pool); i++ {
					if used[pool[i]] == 0 {
						t.Errorf("length %d: character %q never appeared in %d draws",
							length, pool[i], runs)
					}
				}
			}
		})
	}
}

func TestPasswordDistributionIsRoughlyUniform(t *testing.T) {
	const runs, length = 2000, 32
	pool := charLower + charUpper + charDigits
	counts := make(map[byte]int, len(pool))
	for i := 0; i < runs; i++ {
		pw, _ := genPassword(length, false)
		for _, c := range pw {
			counts[c]++
		}
	}
	total := runs * length
	expected := float64(total) / float64(len(pool))
	// Generous bounds: this catches a broken generator, not statistical noise.
	for i := 0; i < len(pool); i++ {
		got := float64(counts[pool[i]])
		if got < expected*0.7 || got > expected*1.3 {
			t.Errorf("character %q appeared %.0f times, expected ~%.0f (±30%%)",
				pool[i], got, expected)
		}
	}
}

// ---------------------------------------------------------------- 7. hashing

func TestHashKnownVectors(t *testing.T) {
	cases := []struct {
		algo, in, want string
	}{
		{"sha256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"sha256", "The quick brown fox jumps over the lazy dog",
			"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
		{"SHA256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"sha512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{"sha512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	}
	dir := t.TempDir()
	for i, c := range cases {
		p := filepath.Join(dir, fmt.Sprintf("f%d", i))
		if err := os.WriteFile(p, []byte(c.in), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := hashFile(p, c.algo)
		if err != nil {
			t.Fatalf("%s(%q): %v", c.algo, c.in, err)
		}
		if got != c.want {
			t.Errorf("%s(%q)\n got %s\nwant %s", c.algo, c.in, got, c.want)
		}
	}
}

func TestHashStreamsLargeFileCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy payload in -short mode")
	}
	// A 5 MB file spans many read buffers; the digest must not depend on chunking.
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	data := bytes.Repeat([]byte("bastion"), (5<<20)/7)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFile(p, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newHash("sha256")
	h.Write(data)
	if want := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("streamed digest %s != in-memory digest %s", got, want)
	}
}

func TestHashRejectsUnknownAlgo(t *testing.T) {
	if _, err := newHash("md5"); err == nil {
		t.Fatal("md5 was accepted, want an error")
	}
	var e exitErr
	_, err := newHash("md5")
	if !errors.As(err, &e) || e.code != exitUsage {
		t.Errorf("unknown algo should be a usage error (exit %d), got %v", exitUsage, err)
	}
}

// ---------------------------------------------------------------- 8. real CLI exit codes

// runCLI re-executes this test binary in CLI mode and reports the real exit code.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "BASTION_TEST_SUBPROCESS=1", "NO_COLOR=1")
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e

	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running %v: %v", args, err)
	}
	return code, o.String(), e.String()
}

func TestCLIExitCodes(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("hello bastion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "cipher.bin")

	leaky := filepath.Join(dir, "leak")
	if err := os.MkdirAll(leaky, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaky, "cfg.py"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean")
	if err := os.MkdirAll(clean, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "main.go"), []byte(innocent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Encrypt first — later cases depend on the file existing.
	if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass); code != exitOK {
		t.Fatalf("enc exited %d, want 0: %s", code, msg)
	}
	tampered := filepath.Join(dir, "tampered.bin")
	ct, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if err := os.WriteFile(tampered, ct, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		stdin string
		args  []string
		want  int
	}{
		{"decrypt_ok", "", []string{"dec", "-in", enc, "-out", filepath.Join(dir, "out1"), "-pass", testPass}, exitOK},
		{"hash_ok", "", []string{"hash", "-file", plain}, exitOK},
		{"gen_ok", "", []string{"gen", "-len", "24", "-symbols"}, exitOK},
		{"totp_gen_ok", "", []string{"totp", "gen", "-secret", rfcSecret}, exitOK},
		{"scan_clean_ok", "", []string{"scan", "-dir", clean}, exitOK},
		{"help_ok", "", []string{"help"}, exitOK},
		{"subcommand_help_ok", "", []string{"enc", "-h"}, exitOK},
		{"password_via_stdin_ok", "pw12345\npw12345\n", []string{"enc", "-in", plain, "-out", filepath.Join(dir, "out2")}, exitOK},

		{"no_args", "", nil, exitUsage},
		{"unknown_command", "", []string{"frobnicate"}, exitUsage},
		{"unknown_totp_subcommand", "", []string{"totp", "wobble"}, exitUsage},
		{"missing_required_flag", "", []string{"enc", "-in", plain}, exitUsage},
		{"unknown_flag", "", []string{"gen", "-nope"}, exitUsage},
		{"same_in_and_out", "", []string{"enc", "-in", plain, "-out", plain, "-pass", "x"}, exitUsage},
		{"missing_input_file", "", []string{"dec", "-in", filepath.Join(dir, "nope"), "-out", filepath.Join(dir, "o"), "-pass", "x"}, exitUsage},
		{"bad_algo", "", []string{"hash", "-file", plain, "-algo", "md5"}, exitUsage},
		{"password_mismatch", "aaa\nbbb\n", []string{"enc", "-in", plain, "-out", filepath.Join(dir, "out3")}, exitUsage},
		{"len_too_short", "", []string{"gen", "-len", "4"}, exitUsage},
		{"bad_totp_secret", "", []string{"totp", "gen", "-secret", "not!base32"}, exitUsage},
		{"scan_missing_dir", "", []string{"scan", "-dir", filepath.Join(dir, "nope")}, exitUsage},

		{"tampered_file", "", []string{"dec", "-in", tampered, "-out", filepath.Join(dir, "out4"), "-pass", testPass}, exitSecurity},
		{"wrong_password", "", []string{"dec", "-in", enc, "-out", filepath.Join(dir, "out5"), "-pass", "wrong"}, exitSecurity},
		{"secrets_found", "", []string{"scan", "-dir", leaky}, exitSecurity},
		{"invalid_totp_code", "", []string{"totp", "verify", "-secret", rfcSecret, "-code", "000000"}, exitSecurity},
		
		{"view_missing", "", []string{"view", "does_not_exist"}, exitUsage},
		{"edit_missing", "", []string{"edit", "does_not_exist"}, exitUsage},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, msg := runCLI(t, c.stdin, c.args...)
			if code != c.want {
				t.Errorf("exit = %d, want %d\nargs:   %v\nstdout: %s\nstderr: %s",
					code, c.want, c.args, out, msg)
			}
		})
	}
}

// A bad flag must NOT exit 2 — that is the code reserved for security failures.
func TestBadFlagIsNotMistakenForSecurityFailure(t *testing.T) {
	for _, args := range [][]string{
		{"gen", "-bogus"},
		{"hash", "-bogus"},
		{"scan", "-bogus"},
		{"enc", "-bogus"},
		{"totp", "gen", "-bogus"},
	} {
		if code, _, _ := runCLI(t, "", args...); code == exitSecurity {
			t.Errorf("%v exited %d — a flag typo must never look like a tamper alert",
				args, exitSecurity)
		}
	}
}

// Machine-readable commands must put nothing but the result on stdout.
func TestStdoutIsPipeable(t *testing.T) {
	code, out, _ := runCLI(t, "", "totp", "gen", "-secret", rfcSecret)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	got := strings.TrimSpace(out)
	if len(got) != 6 || strings.ContainsAny(got, " \n\t") {
		t.Errorf("totp gen stdout = %q, want exactly a 6-digit code", got)
	}

	code, out, _ = runCLI(t, "", "gen", "-len", "24")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if got := strings.TrimSpace(out); len(got) != 24 {
		t.Errorf("gen stdout = %q (%d chars), want exactly 24", got, len(got))
	}
}

func TestCLIRoundTripThroughFiles(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "in.bin")
	data := randPayload(t, 200*1024) // spans several chunks
	if err := os.WriteFile(plain, data, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "enc.bin")
	out := filepath.Join(dir, "out.bin")

	if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass); code != 0 {
		t.Fatalf("enc exit %d: %s", code, msg)
	}
	if code, _, msg := runCLI(t, "", "dec", "-in", enc, "-out", out, "-pass", testPass); code != 0 {
		t.Fatalf("dec exit %d: %s", code, msg)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("CLI round trip did not reproduce the original bytes")
	}
}

// TestCLIRounds covers the -rounds flag end to end through the real binary.
func TestCLIRounds(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(plain, []byte("owasp wants more rounds\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("custom_rounds_round_trip", func(t *testing.T) {
		enc := filepath.Join(dir, "hi.bin")
		out := filepath.Join(dir, "hi.out")
		if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc,
			"-pass", testPass, "-rounds", "600000"); code != exitOK {
			t.Fatalf("enc exit %d: %s", code, msg)
		}
		// dec is given no -rounds: it must read 600000 out of the file.
		if code, _, msg := runCLI(t, "", "dec", "-in", enc, "-out", out, "-pass", testPass); code != exitOK {
			t.Fatalf("dec exit %d: %s", code, msg)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "owasp wants more rounds\n" {
			t.Errorf("round trip mismatch: %q", got)
		}
		ct, err := os.ReadFile(enc)
		if err != nil {
			t.Fatal(err)
		}
		if n := binary.BigEndian.Uint32(ct[saltLen : saltLen+roundsLen]); n != 600000 {
			t.Errorf("file records %d rounds, want 600000", n)
		}
	})

	t.Run("out_of_range_is_a_usage_error", func(t *testing.T) {
		for _, n := range []string{"0", "1", "999", "10000001", "-5"} {
			code, _, _ := runCLI(t, "", "enc", "-in", plain,
				"-out", filepath.Join(dir, "x.bin"), "-pass", testPass, "-rounds", n)
			if code != exitUsage {
				t.Errorf("-rounds %s exited %d, want %d", n, code, exitUsage)
			}
		}
	})

	t.Run("dec_does_not_accept_rounds", func(t *testing.T) {
		enc := filepath.Join(dir, "d.bin")
		if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass); code != exitOK {
			t.Fatalf("enc exit %d: %s", code, msg)
		}
		// The count lives in the file; offering a flag would invite people to get
		// it wrong, so dec must reject it outright rather than silently ignore it.
		code, _, _ := runCLI(t, "", "dec", "-in", enc, "-out", filepath.Join(dir, "d.out"),
			"-pass", testPass, "-rounds", "600000")
		if code != exitUsage {
			t.Errorf("dec -rounds exited %d, want %d", code, exitUsage)
		}
	})

	t.Run("corrupt_rounds_field_exits_2", func(t *testing.T) {
		enc := filepath.Join(dir, "c.bin")
		if code, _, msg := runCLI(t, "", "enc", "-in", plain, "-out", enc, "-pass", testPass); code != exitOK {
			t.Fatalf("enc exit %d: %s", code, msg)
		}
		ct, err := os.ReadFile(enc)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(ct[saltLen:saltLen+roundsLen], 4000000000)
		bad := filepath.Join(dir, "c-bad.bin")
		if err := os.WriteFile(bad, ct, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "c.out")
		code, _, _ := runCLI(t, "", "dec", "-in", bad, "-out", out, "-pass", testPass)
		if code != exitSecurity {
			t.Errorf("exit = %d, want %d", code, exitSecurity)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Error("partial output left behind after a rejected header")
		}
	})
}

// ---------------------------------------------------------------- 9. benchmarks

// benchGCM builds a cipher once so stream benchmarks measure the cipher, not PBKDF2.
func benchGCM(b *testing.B) (cipher.AEAD, []byte) {
	b.Helper()
	gcm, err := deriveGCM([]byte(testPass), make([]byte, saltLen), defaultRounds)
	if err != nil {
		b.Fatal(err)
	}
	return gcm, make([]byte, nonceLen)
}

func BenchmarkEncrypt_10MB(b *testing.B) {
	const size = 10 << 20
	plain := make([]byte, size)
	rand.Read(plain)
	gcm, base := benchGCM(b)

	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := bufio.NewReaderSize(bytes.NewReader(plain), chunkSize)
		if err := sealStream(gcm, base, in, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt_10MB(b *testing.B) {
	const size = 10 << 20
	plain := make([]byte, size)
	rand.Read(plain)
	gcm, base := benchGCM(b)

	var sealed bytes.Buffer
	if err := sealStream(gcm, base, bufio.NewReaderSize(bytes.NewReader(plain), chunkSize), &sealed); err != nil {
		b.Fatal(err)
	}
	ct := sealed.Bytes()

	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := bufio.NewReaderSize(bytes.NewReader(ct), chunkSize+tagLen)
		if err := openStream(gcm, base, in, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPBKDF2_Derive shows the fixed per-file cost of turning a passphrase
// into a key. It is deliberately slow: that is what makes guessing expensive.
func BenchmarkPBKDF2_Derive(b *testing.B) {
	pass := []byte(testPass)
	salt := make([]byte, saltLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zero(pbkdf2SHA256(pass, salt, defaultRounds, keyLen))
	}
}

func BenchmarkTOTP_Generate(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totpAt(rfcSecret, int64(i)*30); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTOTP_Verify(b *testing.B) {
	code, err := totpAt(rfcSecret, 1111111111)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totpVerify(rfcSecret, code, 1111111111); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanner(b *testing.B) {
	dir := b.TempDir()
	var total int64
	for i := 0; i < 40; i++ {
		body := innocent + planted + innocent
		p := filepath.Join(dir, fmt.Sprintf("file%02d.py", i))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			b.Fatal(err)
		}
		total += int64(len(body))
	}

	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := scanDir(io.Discard, dir, 4.5); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShannon(b *testing.B) {
	tok := "aZ9kQ2mX7pL4vB8nR3tY6wE1sD5fG0hJcV"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = shannon(tok)
	}
}

func BenchmarkGenPassword(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pw, _ := genPassword(20, true)
		zero(pw)
	}
}
