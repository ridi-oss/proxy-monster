package result

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// The three ResultCrypto companion constants (ResultCrypto.kt:41-43). TRANSFORM has no Go analogue —
// "AES/GCM/NoPadding" IS crypto/cipher's NewGCM over crypto/aes — and TAG_BITS is not a parameter
// here either: Go's GCM tag is 16 bytes (128 bits) by default, which is exactly what JCE was asked
// for. Both are recorded so the layout stays checkable against the Kotlin.
const (
	// IVLen is the random per-result IV, and therefore the offset the ciphertext starts at inside
	// the stored blob.
	IVLen = 12
	// TagBits is the GCM authentication-tag length the Kotlin requests explicitly and Go supplies by
	// default. cipher.NewGCM's tag is TagBits/8 bytes, appended to the ciphertext by Seal — the same
	// placement JCE's doFinal uses, which is why the two blob layouts are byte-identical.
	TagBits = 128
	// KeyLen is the AES-256 key size ResultCrypto requires.
	KeyLen = 32
)

// ErrKeySize is NewCrypto's rejection of a key that is not 32 bytes — the port of
// `require(keyBytes.size == 32) { "result-encryption key must be 32 bytes (AES-256)" }`.
var ErrKeySize = errors.New("result-encryption key must be 32 bytes (AES-256)")

// ErrCiphertextTooShort is Decrypt's rejection of a blob that cannot even hold an IV — the port of
// `require(blob.size > IV_LEN) { "ciphertext too short" }`. Note the comparison is STRICTLY greater:
// a 12-byte blob is rejected here rather than reaching the cipher.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// Crypto is AES-256-GCM at-rest encryption for APPROVER_EXEC query results — the one path where the
// control plane persists PII-bearing rows. It is the port of `class ResultCrypto(keyBytes: ByteArray)`
// (ResultCrypto.kt, 45 LOC; 07-tasks-approvals-results.md §3).
//
// The stored blob is `iv(12) || ciphertext+tag`. The key comes from PM_RESULT_KEY (env, 32 bytes);
// when it is unset [Store] is not constructed at all and approver-exec execution is refused
// fail-closed — that wiring belongs to A1, not here.
//
// 🔒 INV-A7-6 — GCM gives confidentiality AND integrity: a tampered blob fails to decrypt rather than
// yielding garbage, and a per-result random IV keeps identical results from producing identical blobs.
//
// ⚠️ Deviation, language-forced: the Kotlin builds a fresh `Cipher` per call because javax.crypto's
// Cipher is stateful and not thread-safe. Go's cipher.AEAD is stateless and explicitly safe for
// concurrent use, so the GCM instance is built once in NewCrypto. Unobservable: the same key, the
// same nonce size, the same tag length, the same bytes.
type Crypto struct {
	gcm cipher.AEAD
}

// NewCrypto is the ResultCrypto constructor. Kotlin's `init { require(...) }` throws
// IllegalArgumentException on a bad key length; Go has no exceptions, so the check becomes a returned
// error — the one place in this file the shape had to change.
func NewCrypto(key []byte) (*Crypto, error) {
	if len(key) != KeyLen {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("result: build AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("result: build GCM: %w", err)
	}
	// A defensive assertion, not a port: if the stdlib's default nonce size ever stopped being 12 the
	// blob layout would silently stop matching the Kotlin's, and every previously stored result would
	// become undecryptable rather than failing here.
	if gcm.NonceSize() != IVLen {
		return nil, fmt.Errorf("result: GCM nonce is %d bytes, the stored layout needs %d", gcm.NonceSize(), IVLen)
	}
	return &Crypto{gcm: gcm}, nil
}

// Encrypt returns `iv || ciphertext+tag`, with a fresh random 12-byte IV.
//
// `gcm.Seal(nonce, nonce, pt, nil)` reproduces the Kotlin's `iv + cipher.doFinal(plaintext)` exactly:
// Seal appends ciphertext-then-tag to its dst, and passing the nonce as dst puts the IV in front.
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	iv := make([]byte, IVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("result: read IV: %w", err)
	}
	return c.gcm.Seal(iv, iv, plaintext, nil), nil
}

// Decrypt splits the blob at IVLen and authenticates. A tampered blob, a truncated tag or the wrong
// key all fail here (INV-A7-6) rather than returning bytes.
func (c *Crypto) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) <= IVLen {
		return nil, ErrCiphertextTooShort
	}
	out, err := c.gcm.Open(nil, blob[:IVLen], blob[IVLen:], nil)
	if err != nil {
		return nil, fmt.Errorf("result: decrypt: %w", err)
	}
	return out, nil
}
