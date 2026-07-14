package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/certificates"
)

func TestReadBundleRejectsOversizedOpenedFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certificate.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, make([]byte, certificates.MaxPEMBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBundle(certPath, keyPath, "")
	if err == nil || !strings.Contains(err.Error(), "no larger than 256 KiB") {
		t.Fatalf("ReadBundle error = %v, want bounded-read rejection", err)
	}
}

func TestReadBundleRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certificate.pem")
	if err := os.WriteFile(certPath, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBundle(certPath, dir, "")
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("ReadBundle error = %v, want regular-file rejection", err)
	}
}
