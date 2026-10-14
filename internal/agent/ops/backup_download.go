package ops

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type BackupDownloadReader struct{ root string }

func NewBackupDownloadReader(root string) *BackupDownloadReader {
	return &BackupDownloadReader{root: defaultPath(root, "/var/lib/nakpanel/backups")}
}
func (p *BackupDownloadReader) ReadBackupChunk(ctx context.Context, req types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error) {
	result := types.ReadBackupChunkResult{SHA256: req.SHA256, BackupID: req.BackupID, Offset: req.Offset}
	if req.BackupID <= 0 || req.SubscriptionID <= 0 || req.Offset < 0 || req.Limit <= 0 || req.Limit > 512<<10 || site.ValidateDomain(req.Domain) != nil || req.Domain != site.NormalizeDomain(req.Domain) || !recoveryChecksumRE.MatchString(req.SHA256) {
		return result, errors.New("invalid backup download identity or bounds")
	}
	path := filepath.Clean(req.ArchivePath)
	if !filepath.IsAbs(path) || path != req.ArchivePath || filepath.Dir(path) != p.root || !strings.HasPrefix(filepath.Base(path), req.Domain+"-") || !strings.HasSuffix(path, ".tar.gz") {
		return result, errors.New("backup download is outside managed storage")
	}
	if err := validateRemovalArtifact(removalArtifact{root: p.root, path: path}); err != nil {
		return result, errors.New("backup download storage is unavailable")
	}
	file, err := openSiteIdentityRead(path)
	if err != nil {
		return result, errors.New("backup archive is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !siteIdentityOwnedByAgent(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 256<<30 || req.Offset > info.Size() {
		return result, errors.New("backup archive is not protected managed data")
	}
	if req.Offset == 0 {
		if err = verifyRestoreChecksum(ctx, path, req.SHA256); err != nil {
			return result, errors.New("backup archive checksum did not verify")
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	data := make([]byte, req.Limit)
	n, err := file.ReadAt(data, req.Offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return result, errors.New("could not read backup archive")
	}
	result.Size = info.Size()
	result.Data = data[:n]
	return result, nil
}
