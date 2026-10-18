package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReviewedLegacyProvenanceBoundToArchive(t *testing.T) {
	key := testKey(t)
	var buf bytes.Buffer
	w, _ := NewArchiveWriter(&buf, key)
	_ = w.AddBytes(ManifestName, []byte(`{"format_version":1}`), 0600)
	_ = w.Close()
	sum := sha256.Sum256(buf.Bytes())
	review := ProvenanceReview{ArchiveSHA256: hex.EncodeToString(sum[:]), ReviewedBy: "recovery operator", Platform: platformFixture("24.04")}
	data, _ := json.Marshal(review)
	got, err := ReadProvenanceReview(bytes.NewReader(data), func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil })
	if err != nil || got.OSID != "ubuntu" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	review.ArchiveSHA256 = strings.Repeat("0", 64)
	data, _ = json.Marshal(review)
	if _, err = ReadProvenanceReview(bytes.NewReader(data), func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil }); err == nil {
		t.Fatal("accepted review of another archive")
	}
	review.ArchiveSHA256 = hex.EncodeToString(sum[:])
	review.ReviewedBy = ""
	data, _ = json.Marshal(review)
	if _, err = ReadProvenanceReview(bytes.NewReader(data), func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil }); err == nil {
		t.Fatal("accepted unreviewed provenance")
	}
}
