package ops

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSiteServiceDependenciesFollowConfiguredFTPSCertificate(t *testing.T) {
	root := t.TempDir()
	certRoot := filepath.Join(root, "certs")
	directory := filepath.Join(certRoot, "ftp.test")
	os.MkdirAll(directory, 0700)
	cert := filepath.Join(directory, "fullchain.pem")
	os.WriteFile(cert, []byte("not read as certificate"), 0600)
	link := filepath.Join(root, "proftpd-cert.pem")
	if err := os.Symlink(cert, link); err != nil {
		t.Fatal(err)
	}
	reader := NewSiteServiceDependencyReader(SiteServiceDependencyOptions{CertRoot: certRoot, HomeRoot: filepath.Join(root, "home"), FTPSConfigPath: filepath.Join(root, "absent-proftpd.conf"), Paths: []string{link}, Hostnames: []string{"mail.test"}})
	domains, err := reader.SiteServiceDependencies(context.Background())
	if err != nil || !slices.Contains(domains, "ftp.test") || !slices.Contains(domains, "mail.test") {
		t.Fatalf("dependencies=%v %v", domains, err)
	}
}

func TestSiteServiceDependenciesReadActiveFTPSConfiguration(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "proftpd.conf")
	certRoot := filepath.Join(root, "certs")
	if err := os.WriteFile(config, []byte("TLSRSACertificateFile "+filepath.Join(certRoot, "actual.test", "fullchain.pem")+"\nTLSRSACertificateKeyFile "+filepath.Join(certRoot, "actual.test", "privkey.pem")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reader := NewSiteServiceDependencyReader(SiteServiceDependencyOptions{CertRoot: certRoot, FTPSConfigPath: config})
	domains, err := reader.SiteServiceDependencies(context.Background())
	if err != nil || !slices.Contains(domains, "actual.test") {
		t.Fatalf("active certificate dependency=%v %v", domains, err)
	}
}
