package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ProvenanceReview binds reconstructed observations of a legacy source to the
// exact encrypted archive. The reviewer must independently inspect the intact
// source host and required runtime inventory; this is never an unknown-field bypass.
type ProvenanceReview struct {
	ArchiveSHA256 string             `json:"archive_sha256"`
	ReviewedBy    string             `json:"reviewed_by"`
	Platform      PlatformProvenance `json:"platform"`
}

func ReadProvenanceReview(src io.Reader, openArchive func() (io.ReadCloser, error)) (PlatformProvenance, error) {
	var r ProvenanceReview
	decoder := json.NewDecoder(io.LimitReader(src, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r.Platform, fmt.Errorf("provenance review: %w", err)
	}
	if strings.TrimSpace(r.ReviewedBy) == "" || len(r.ArchiveSHA256) != 64 {
		return r.Platform, errors.New("provenance review requires reviewer and archive SHA256")
	}
	if _, err := hex.DecodeString(r.ArchiveSHA256); err != nil {
		return r.Platform, errors.New("invalid review archive SHA256")
	}
	file, err := openArchive()
	if err != nil {
		return r.Platform, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return r.Platform, err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), r.ArchiveSHA256) {
		return r.Platform, errors.New("provenance review does not match encrypted archive SHA256")
	}
	return r.Platform, nil
}

// ApplyProvenanceReview is permitted only for an otherwise legacy archive in
// explicit forward mode. CheckRestoreCompatibility still requires every field.
func ApplyProvenanceReview(m Manifest, mode RestoreMode, review io.Reader, openArchive func() (io.ReadCloser, error)) (Manifest, error) {
	if review == nil {
		return m, nil
	}
	if mode != RestoreForwardMigration || m.Platform != nil {
		return m, errors.New("source provenance review is only valid for legacy forward-migration archives")
	}
	p, err := ReadProvenanceReview(review, openArchive)
	if err != nil {
		return m, err
	}
	m.Platform = &p
	return m, nil
}
