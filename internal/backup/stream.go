// Package backup implements nakpanel's server-level backup primitives: the
// authenticated encryption stream every archive is wrapped in, the archive
// writer/reader, the destination transports (local, SFTP, S3), and the
// disaster-recovery restore engine.
//
// The stream format ("NKBK", version 1) is a chunked AES-256-GCM construction
// in the style of Tink/age STREAM: a random 16-byte file id salts an
// HKDF-SHA256 derivation of the per-file key, and every chunk is sealed with
// a nonce made of an 11-byte big-endian counter plus a final-chunk flag byte.
// Truncation, reordering, and chunk substitution all fail authentication.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	streamMagic   = "NKBK"
	streamVersion = 1
	fileIDSize    = 16
	headerSize    = 4 + 1 + fileIDSize

	// ChunkSize is the plaintext chunk size. The final chunk may be shorter
	// (and may be empty for an empty stream).
	ChunkSize = 1 << 20

	gcmTagSize        = 16
	maxCiphertextSize = ChunkSize + gcmTagSize

	hkdfInfo = "nakpanel-server-backup-v1"
)

// KeySize is the required master key length in bytes.
const KeySize = 32

var (
	// ErrBadKey indicates the master key is malformed.
	ErrBadKey = errors.New("backup: master key must be 32 bytes")
	// ErrCorrupt indicates the stream failed authentication or framing.
	ErrCorrupt = errors.New("backup: stream is corrupt or the key is wrong")
	// ErrTruncated indicates the stream ended before its final chunk.
	ErrTruncated = errors.New("backup: stream is truncated")
)

func deriveAEAD(masterKey, fileID []byte) (cipher.AEAD, error) {
	if len(masterKey) != KeySize {
		return nil, ErrBadKey
	}
	derived := make([]byte, KeySize)
	kdf := hkdf.New(sha256.New, masterKey, fileID, []byte(hkdfInfo))
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(counter uint64, final bool) []byte {
	nonce := make([]byte, 12)
	// 11-byte big-endian counter (top 3 bytes always zero at realistic sizes).
	binary.BigEndian.PutUint64(nonce[3:11], counter)
	if final {
		nonce[11] = 1
	}
	return nonce
}

// StreamWriter encrypts a byte stream into the NKBK chunk format.
type StreamWriter struct {
	dst     io.Writer
	aead    cipher.AEAD
	header  []byte
	buf     []byte
	counter uint64
	closed  bool
	err     error
}

// NewStreamWriter writes the stream header and returns a writer that seals
// data in ChunkSize chunks. Close MUST be called to emit the authenticated
// final chunk; without it the stream is detectably truncated.
func NewStreamWriter(dst io.Writer, masterKey []byte) (*StreamWriter, error) {
	fileID := make([]byte, fileIDSize)
	if _, err := rand.Read(fileID); err != nil {
		return nil, err
	}
	aead, err := deriveAEAD(masterKey, fileID)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, headerSize)
	header = append(header, streamMagic...)
	header = append(header, streamVersion)
	header = append(header, fileID...)
	if _, err := dst.Write(header); err != nil {
		return nil, err
	}
	return &StreamWriter{
		dst:    dst,
		aead:   aead,
		header: header,
		buf:    make([]byte, 0, ChunkSize),
	}, nil
}

func (w *StreamWriter) flushChunk(final bool) error {
	nonce := chunkNonce(w.counter, final)
	sealed := w.aead.Seal(nil, nonce, w.buf, w.header)
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], uint32(len(sealed)))
	if _, err := w.dst.Write(frame[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(sealed); err != nil {
		return err
	}
	w.counter++
	w.buf = w.buf[:0]
	return nil
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("backup: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		space := ChunkSize - len(w.buf)
		n := len(p)
		if n > space {
			n = space
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		if len(w.buf) == ChunkSize {
			// Never flush a full chunk as non-final until more data arrives;
			// a stream whose length is an exact multiple of ChunkSize ends
			// with an empty final chunk instead.
			if err := w.flushChunk(false); err != nil {
				w.err = err
				return 0, err
			}
		}
	}
	return total, nil
}

// Close seals the final chunk. The final chunk may be empty.
func (w *StreamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	return w.flushChunk(true)
}

// StreamReader decrypts and authenticates an NKBK stream.
type StreamReader struct {
	src     io.Reader
	aead    cipher.AEAD
	header  []byte
	plain   bytes.Reader
	counter uint64
	done    bool
}

// NewStreamReader validates the header and prepares chunked decryption.
func NewStreamReader(src io.Reader, masterKey []byte) (*StreamReader, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(src, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncated
		}
		return nil, err
	}
	if string(header[:4]) != streamMagic {
		return nil, fmt.Errorf("backup: not an NKBK stream")
	}
	if header[4] != streamVersion {
		return nil, fmt.Errorf("backup: unsupported stream version %d", header[4])
	}
	aead, err := deriveAEAD(masterKey, header[5:5+fileIDSize])
	if err != nil {
		return nil, err
	}
	return &StreamReader{src: src, aead: aead, header: header}, nil
}

func (r *StreamReader) nextChunk() error {
	var frame [4]byte
	if _, err := io.ReadFull(r.src, frame[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return err
	}
	size := binary.BigEndian.Uint32(frame[:])
	if size < gcmTagSize || size > maxCiphertextSize {
		return ErrCorrupt
	}
	sealed := make([]byte, size)
	if _, err := io.ReadFull(r.src, sealed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return err
	}
	// Try the non-final nonce first; fall back to the final nonce. A chunk
	// authenticating under neither means corruption or a wrong key.
	plain, err := r.aead.Open(nil, chunkNonce(r.counter, false), sealed, r.header)
	if err != nil {
		plain, err = r.aead.Open(nil, chunkNonce(r.counter, true), sealed, r.header)
		if err != nil {
			return ErrCorrupt
		}
		r.done = true
	}
	r.counter++
	r.plain.Reset(plain)
	return nil
}

func (r *StreamReader) Read(p []byte) (int, error) {
	for {
		if r.plain.Len() > 0 {
			return r.plain.Read(p)
		}
		if r.done {
			// Enforce a clean end: trailing bytes after the final chunk are
			// an integrity failure.
			var extra [1]byte
			if n, _ := r.src.Read(extra[:]); n > 0 {
				return 0, ErrCorrupt
			}
			return 0, io.EOF
		}
		if err := r.nextChunk(); err != nil {
			return 0, err
		}
	}
}
