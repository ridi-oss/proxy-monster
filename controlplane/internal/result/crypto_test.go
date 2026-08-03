package result

import (
	"bytes"
	"errors"
	"testing"
)

// ResultCryptoTest.kt — 7 cases, pure unit, no DB. Ported first because it validates the exact
// `iv || ct+tag` layout the Go implementation has to reproduce (07-tasks-approvals-results.md §10).

// testKey is the Kotlin's `ByteArray(32) { it.toByte() }` — 0x00..0x1f.
func testKey() []byte {
	k := make([]byte, KeyLen)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func newTestCrypto(t *testing.T) *Crypto {
	t.Helper()
	c, err := NewCrypto(testKey())
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	return c
}

// 1. round-trips plaintext
func TestCryptoRoundTripsPlaintext(t *testing.T) {
	c := newTestCrypto(t)
	plain := []byte("rrn=900101-1234567")
	blob, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Errorf("round trip = %q, want %q", got, plain)
	}
}

// 2. ciphertext is not the plaintext and uses a random iv
func TestCryptoCiphertextIsNotPlaintextAndUsesARandomIV(t *testing.T) {
	c := newTestCrypto(t)
	plain := []byte("900101-1234567")
	a, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("same plaintext must not produce identical blobs (random IV)")
	}
	if bytes.Equal(a[IVLen:], plain) {
		t.Error("ciphertext must not equal plaintext")
	}
	// Layout: the Kotlin's `a.drop(12)` is only the ciphertext if the IV really is the first 12
	// bytes, so pin the total length too — iv + plaintext + 16-byte tag.
	if want := IVLen + len(plain) + TagBits/8; len(a) != want {
		t.Errorf("blob is %d bytes, want %d (iv %d + ct %d + tag %d)", len(a), want, IVLen, len(plain), TagBits/8)
	}
}

// 3. 🔒 tampered ciphertext fails to decrypt
func TestCryptoTamperedCiphertextFailsToDecrypt(t *testing.T) {
	c := newTestCrypto(t)
	blob, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob[len(blob)-1] ^= 0x01
	if got, err := c.Decrypt(blob); err == nil {
		t.Errorf("Decrypt(tampered) = %q, want an error", got)
	}
}

// 4. 🔒 wrong key fails to decrypt
func TestCryptoWrongKeyFailsToDecrypt(t *testing.T) {
	c := newTestCrypto(t)
	blob, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	otherKey := make([]byte, KeyLen)
	for i := range otherKey {
		otherKey[i] = byte(i + 1)
	}
	other, err := NewCrypto(otherKey)
	if err != nil {
		t.Fatalf("NewCrypto(other): %v", err)
	}
	if got, err := other.Decrypt(blob); err == nil {
		t.Errorf("Decrypt(wrong key) = %q, want an error", got)
	}
}

// 5. key must be 32 bytes
func TestCryptoKeyMustBe32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewCrypto(make([]byte, n)); !errors.Is(err, ErrKeySize) {
			t.Errorf("NewCrypto(%d bytes) error = %v, want ErrKeySize", n, err)
		}
	}
}

// 6. too-short blob is rejected
func TestCryptoTooShortBlobIsRejected(t *testing.T) {
	c := newTestCrypto(t)
	if _, err := c.Decrypt(make([]byte, 8)); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Decrypt(8 bytes) error = %v, want ErrCiphertextTooShort", err)
	}
	// `require(blob.size > IV_LEN)` is strictly greater, so a bare IV is rejected by the guard and
	// never reaches the cipher.
	if _, err := c.Decrypt(make([]byte, IVLen)); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Decrypt(%d bytes) error = %v, want ErrCiphertextTooShort", IVLen, err)
	}
}

// 7. empty plaintext round-trips
func TestCryptoEmptyPlaintextRoundTrips(t *testing.T) {
	c := newTestCrypto(t)
	blob, err := c.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty round trip = %q, want empty", got)
	}
}
