package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func encrypt(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewStreamWriter(&buf, key)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	r, err := NewStreamReader(bytes.NewReader(ciphertext), key)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestStreamRoundTrip(t *testing.T) {
	key := testKey(t)
	sizes := []int{0, 1, 100, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 17}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		got, err := decrypt(key, encrypt(t, key, plaintext))
		if err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestStreamWrongKeyFails(t *testing.T) {
	ciphertext := encrypt(t, testKey(t), []byte("secret payload"))
	if _, err := decrypt(testKey(t), ciphertext); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt with wrong key, got %v", err)
	}
}

func TestStreamTruncationDetected(t *testing.T) {
	key := testKey(t)
	plaintext := make([]byte, 2*ChunkSize+50)
	ciphertext := encrypt(t, key, plaintext)
	for _, cut := range []int{len(ciphertext) - 1, len(ciphertext) - 20, headerSize + 10, headerSize} {
		if _, err := decrypt(key, ciphertext[:cut]); err == nil {
			t.Fatalf("truncation at %d not detected", cut)
		}
	}
	// Dropping the whole final chunk (clean frame boundary) must also fail.
	// The final chunk here carries the trailing 50 bytes.
	finalFrame := 4 + 50 + gcmTagSize
	if _, err := decrypt(key, ciphertext[:len(ciphertext)-finalFrame]); !errors.Is(err, ErrTruncated) {
		t.Fatalf("dropped final chunk: want ErrTruncated, got %v", err)
	}
}

func TestStreamTamperDetected(t *testing.T) {
	key := testKey(t)
	ciphertext := encrypt(t, key, bytes.Repeat([]byte("a"), ChunkSize+100))
	tampered := append([]byte(nil), ciphertext...)
	tampered[headerSize+10] ^= 0x01
	if _, err := decrypt(key, tampered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt after tamper, got %v", err)
	}
}

func TestStreamReorderDetected(t *testing.T) {
	key := testKey(t)
	plaintext := make([]byte, 2*ChunkSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext := encrypt(t, key, plaintext)
	// Layout: header | frame0 | frame1 | final(empty). Swap frame 0 and 1.
	frameLen := 4 + ChunkSize + gcmTagSize
	swapped := append([]byte(nil), ciphertext[:headerSize]...)
	swapped = append(swapped, ciphertext[headerSize+frameLen:headerSize+2*frameLen]...)
	swapped = append(swapped, ciphertext[headerSize:headerSize+frameLen]...)
	swapped = append(swapped, ciphertext[headerSize+2*frameLen:]...)
	if _, err := decrypt(key, swapped); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt after reorder, got %v", err)
	}
}

func TestStreamTrailingGarbageDetected(t *testing.T) {
	key := testKey(t)
	ciphertext := encrypt(t, key, []byte("payload"))
	if _, err := decrypt(key, append(ciphertext, 0x00)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt with trailing bytes, got %v", err)
	}
}

func TestKeyEncodeDecode(t *testing.T) {
	key := testKey(t)
	encoded, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "nkbk1-") {
		t.Fatalf("unexpected encoding %q", encoded)
	}
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("key round trip mismatch")
	}
	if _, err := DecodeKey("garbage"); err == nil {
		t.Fatal("expected error for malformed key")
	}
	if len(Fingerprint(key)) != 16 {
		t.Fatalf("fingerprint length %d", len(Fingerprint(key)))
	}
}
