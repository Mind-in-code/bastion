# BASTION INVARIANTS:
1. ZERO external/third-party runtime dependencies. Standard library ONLY (`crypto/*`, `encoding/*`, `flag`, `os`, `io`, `sync`, `math`, `regexp`, `bufio`, `testing`).
2. Single-file implementation: All production logic MUST live in `bastion.go`.
3. Minimalist, idiomatic Go: No unnecessary struct wrappers, empty interfaces, or boilerplate.
4. Security Invariants: Fail closed on error (exit code 2 for tampering/security failure). Zero out secret buffers immediately. Use `crypto/subtle.ConstantTimeCompare`.
5. Low Memory / Streaming: Use chunked streaming (`io.Copy`, `bufio`) so file encryption/decryption uses O(1) memory.
