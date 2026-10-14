package ops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var recoveryChecksumRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

type removalRecoveryReader struct {
	context context.Context
	reader  io.Reader
}

func (r removalRecoveryReader) Read(p []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (p *SiteTeardownProvisioner) verifyToolkitRecoveryBackups(ctx context.Context, req types.TeardownSiteReq) error {
	for _, database := range req.Snapshot.Databases {
		if !slices.Contains(req.DeleteDatabaseIDs, database.ID) || database.Provenance != "wordpress_toolkit" {
			continue
		}
		var proof *types.SiteRemovalResource
		for i := range req.Snapshot.Backups {
			if req.Snapshot.Backups[i].ID == database.RecoveryBackupID {
				proof = &req.Snapshot.Backups[i]
				break
			}
		}
		if proof == nil || proof.ParentID != req.SubscriptionID || proof.Mode != "active" || !recoveryChecksumRE.MatchString(proof.SHA256) || !slices.Contains(proof.DatabaseNames, database.Name) {
			return errors.New("Toolkit database requires an active verified recovery archive")
		}
		if err := p.verifyRemovalRecoveryArchive(ctx, *proof, database.Name); err != nil {
			return err
		}
	}
	return nil
}

func (p *SiteTeardownProvisioner) verifyRemovalRecoveryArchive(ctx context.Context, proof types.SiteRemovalResource, database string) error {
	if proof.Kind != "backup" || proof.ID <= 0 || site.ValidateDomain(proof.Name) != nil || proof.Name != site.NormalizeDomain(proof.Name) {
		return errors.New("recovery backup identity is invalid")
	}
	path := filepath.Clean(proof.ArchivePath)
	if !filepath.IsAbs(path) || filepath.Dir(path) != p.options.BackupRoot || !strings.HasPrefix(filepath.Base(path), proof.Name+"-") || !strings.HasSuffix(path, ".tar.gz") {
		return errors.New("recovery archive is outside the managed backup root")
	}
	if err := validateRemovalArtifact(removalArtifact{root: p.options.BackupRoot, path: path}); err != nil {
		return err
	}
	file, err := openSiteIdentityRead(path)
	if err != nil {
		return errors.New("recovery archive is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !siteIdentityOwnedByAgent(info) || info.Mode().Perm()&0022 != 0 || info.Size() > 256<<30 {
		return errors.New("recovery archive is not protected agent-owned data")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, removalRecoveryReader{context: ctx, reader: file}); err != nil {
		return errors.New("recovery archive verification failed")
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != proof.SHA256 {
		return errors.New("recovery archive checksum does not match")
	}
	if _, err = file.Seek(0, 0); err != nil {
		return err
	}
	compressed, err := gzip.NewReader(removalRecoveryReader{context: ctx, reader: file})
	if err != nil {
		return errors.New("recovery archive format is invalid")
	}
	defer compressed.Close()
	reader := tar.NewReader(io.LimitReader(compressed, 512<<30))
	header, err := reader.Next()
	if err != nil || header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size > 1<<20 {
		return errors.New("recovery archive manifest is invalid")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.New("recovery manifest cannot be read")
	}
	var manifest struct {
		Domain    string   `json:"domain"`
		Databases []string `json:"databases"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Domain != proof.Name || !slices.Contains(manifest.Databases, database) {
		return errors.New("recovery archive does not cover the selected database")
	}
	found := false
	for {
		header, err = reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("recovery archive is incomplete")
		}
		if header.Name == "databases/"+database+".sql" && header.Typeflag == tar.TypeReg && header.Size > 0 {
			found = true
		}
		if _, err = io.Copy(io.Discard, reader); err != nil {
			return errors.New("recovery archive is incomplete")
		}
	}
	if !found {
		return errors.New("recovery archive has no selected database dump")
	}
	return nil
}

func verifyRestoreChecksum(ctx context.Context, path, want string) error {
	if !recoveryChecksumRE.MatchString(want) {
		return errors.New("restore requires a valid archive checksum")
	}
	file, err := openSiteIdentityRead(path)
	if err != nil {
		return errors.New("restore archive is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<30 {
		return errors.New("restore archive is invalid or exceeds its verification bound")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, removalRecoveryReader{context: ctx, reader: file}); err != nil {
		return errors.New("restore archive checksum could not be verified")
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != want {
		return errors.New("restore archive checksum does not match")
	}
	return nil
}
