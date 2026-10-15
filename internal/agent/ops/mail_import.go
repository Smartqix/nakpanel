package ops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	mailimport "github.com/nakroteck/nakpanel/internal/mailimport"
	"github.com/nakroteck/nakpanel/internal/types"
	"golang.org/x/sys/unix"
)

var mailStageID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type MailImportProvisioner struct{ uploads, root string }

func NewMailImportProvisioner(uploads, root string) *MailImportProvisioner {
	if uploads == "" {
		uploads = "/var/lib/nakpanel/mail-import-uploads"
	}
	if root == "" {
		root = "/var/lib/nakpanel/mail-imports"
	}
	return &MailImportProvisioner{uploads, root}
}
func (p *MailImportProvisioner) stagingRoot(sub int64, id string) (string, error) {
	if sub <= 0 || !mailStageID.MatchString(id) {
		return "", errors.New("invalid Maildir staging identity")
	}
	return filepath.Join(p.root, fmt.Sprintf("sub-%d", sub), id), nil
}
func (p *MailImportProvisioner) StageMaildir(ctx context.Context, req types.StageMaildirReq) (types.StageMaildirResult, error) {
	if req.SubscriptionID <= 0 || !mailStageID.MatchString(req.UploadID) {
		return types.StageMaildirResult{}, errors.New("invalid Maildir upload identity")
	}
	fd, err := unix.Open(filepath.Join(p.uploads, req.UploadID+".tar"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return types.StageMaildirResult{}, errors.New("Maildir upload is unavailable")
	}
	file := os.NewFile(uintptr(fd), "maildir-upload")
	defer file.Close()
	info, err := file.Stat()
	var stat unix.Stat_t
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<20 || unix.Fstat(fd, &stat) != nil || stat.Nlink != 1 {
		return types.StageMaildirResult{}, errors.New("invalid Maildir upload")
	}
	if err = ctx.Err(); err != nil {
		return types.StageMaildirResult{}, err
	}
	if err = os.MkdirAll(p.root, 0700); err != nil {
		return types.StageMaildirResult{}, err
	}
	lock, err := os.OpenFile(filepath.Join(p.root, ".staging.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return types.StageMaildirResult{}, err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return types.StageMaildirResult{}, errors.New("another mail archive is being staged; try again shortly")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	var used int64
	err = filepath.WalkDir(p.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected staging link")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			used += info.Size()
		}
		return nil
	})
	if err != nil || used > 1<<30 {
		return types.StageMaildirResult{}, errors.New("mail archive staging capacity is exhausted")
	}
	var space unix.Statfs_t
	if unix.Statfs(p.root, &space) != nil || space.Bavail*uint64(space.Bsize) < (1<<30)+(256<<20) {
		return types.StageMaildirResult{}, errors.New("insufficient disk space for mail archive staging")
	}
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return types.StageMaildirResult{}, err
	}
	raw := hex.EncodeToString(b)
	id := raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
	root, _ := p.stagingRoot(req.SubscriptionID, id)
	if err = os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return types.StageMaildirResult{}, err
	}
	if err = os.Mkdir(root, 0700); err != nil {
		return types.StageMaildirResult{}, err
	}
	manifest, err := mailimport.ExtractMaildir(file, root, mailimport.ArchiveLimits{Bytes: 1 << 30, Entries: 100000})
	if err != nil {
		_ = os.RemoveAll(root)
		return types.StageMaildirResult{}, err
	}
	return types.StageMaildirResult{StagingID: id, ManifestSHA256: manifest.SHA256, Messages: len(manifest.Messages)}, nil
}
func (p *MailImportProvisioner) RemoveMaildirStage(ctx context.Context, req types.RemoveMaildirStageReq) error {
	if len(req.ManifestSHA256) != 64 {
		return errors.New("Maildir manifest hash is required for cleanup")
	}
	root, err := p.stagingRoot(req.SubscriptionID, req.StagingID)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = os.Lstat(root); os.IsNotExist(err) {
		return nil
	}
	if _, err = mailimport.LoadMaildirManifest(root, req.ManifestSHA256); err != nil {
		return err
	}
	return os.RemoveAll(root)
}
func (p *MailImportProvisioner) InspectMaildir(ctx context.Context, req types.InspectMaildirReq) (types.InspectMaildirResult, error) {
	root, err := p.stagingRoot(req.SubscriptionID, req.StagingID)
	if err != nil {
		return types.InspectMaildirResult{}, err
	}
	if req.Offset < 0 || req.Limit < 1 || req.Limit > 100 || len(req.ManifestSHA256) != 64 {
		return types.InspectMaildirResult{}, errors.New("invalid Maildir page")
	}
	if err = ctx.Err(); err != nil {
		return types.InspectMaildirResult{}, err
	}
	manifest, err := mailimport.LoadMaildirManifest(root, req.ManifestSHA256)
	if err != nil {
		return types.InspectMaildirResult{}, err
	}
	if req.Offset > len(manifest.Messages) {
		return types.InspectMaildirResult{}, errors.New("invalid Maildir cursor")
	}
	end := min(req.Offset+req.Limit, len(manifest.Messages))
	result := types.InspectMaildirResult{Total: len(manifest.Messages), NextOffset: end, ManifestSHA256: manifest.SHA256, Messages: []types.MaildirMessage{}}
	for _, m := range manifest.Messages[req.Offset:end] {
		result.Messages = append(result.Messages, types.MaildirMessage{Key: m.Key, Folder: m.Folder, SHA256: m.SHA256, Size: m.Size, InternalDate: m.InternalDate, Flags: m.Flags})
	}
	return result, nil
}
func (p *MailImportProvisioner) ReadMaildirMessage(ctx context.Context, req types.ReadMaildirMessageReq) (types.ReadMaildirMessageResult, error) {
	root, err := p.stagingRoot(req.SubscriptionID, req.StagingID)
	if err != nil {
		return types.ReadMaildirMessageResult{}, err
	}
	if req.Offset < 0 || req.Limit < 1 || req.Limit > 128<<10 || len(req.ManifestSHA256) != 64 {
		return types.ReadMaildirMessageResult{}, errors.New("invalid Maildir read bounds")
	}
	if err = ctx.Err(); err != nil {
		return types.ReadMaildirMessageResult{}, err
	}
	manifest, err := mailimport.LoadMaildirManifest(root, req.ManifestSHA256)
	if err != nil {
		return types.ReadMaildirMessageResult{}, err
	}
	for _, entry := range manifest.Messages {
		if entry.Key != req.Key {
			continue
		}
		if req.Offset > entry.Size {
			return types.ReadMaildirMessageResult{}, errors.New("invalid Maildir message offset")
		}
		file, err := mailimport.OpenStagedFile(root, entry.Path)
		if err != nil {
			return types.ReadMaildirMessageResult{}, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || info.Size() != entry.Size {
			return types.ReadMaildirMessageResult{}, mailimport.ErrSourceChanged
		}
		data := make([]byte, min(int64(req.Limit), entry.Size-req.Offset))
		_, err = file.ReadAt(data, req.Offset)
		if err != nil && err != io.EOF {
			return types.ReadMaildirMessageResult{}, err
		}
		return types.ReadMaildirMessageResult{Data: data, EOF: req.Offset+int64(len(data)) == entry.Size, SHA256: entry.SHA256}, nil
	}
	return types.ReadMaildirMessageResult{}, errors.New("message is not in the Maildir manifest")
}
