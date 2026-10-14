package panelhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type backupChunkService interface {
	ReadBackupFor(context.Context, auth.SessionUser, int64, int64, int) (types.ReadBackupChunkResult, error)
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if support := r.PathValue("customerID"); support != "" {
		customer, e := strconv.ParseInt(support, 10, 64)
		if e != nil || customer <= 0 || user.Role != auth.RoleAdmin || s.workspace == nil {
			http.NotFound(w, r)
			return
		}
		owner, e := s.workspace.CustomerIDForBackup(r.Context(), id)
		if e != nil || owner != customer {
			http.NotFound(w, r)
			return
		}
	}
	reader, ok := s.phase6.(backupChunkService)
	if !ok {
		http.Error(w, "Backup download is unavailable", 503)
		return
	}
	const limit = 512 << 10
	chunk, err := reader.ReadBackupFor(r.Context(), user, id, 0, limit)
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "The backup archive is unavailable or could not be verified", 503)
		return
	}
	if chunk.BackupID != id || chunk.Offset != 0 || chunk.Size <= 0 || chunk.Size > 256<<30 || len(chunk.Data) == 0 || len(chunk.Data) > limit || int64(len(chunk.Data)) > chunk.Size {
		http.Error(w, "Invalid backup download response", 502)
		return
	}
	checksum := chunk.SHA256
	decoded, err := hex.DecodeString(checksum)
	if err != nil || len(decoded) != sha256.Size {
		http.Error(w, "Invalid backup checksum response", 502)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="backup-%d.tar.gz"`, id))
	w.Header().Set("Content-Length", strconv.FormatInt(chunk.Size, 10))
	size := chunk.Size
	offset := int64(0)
	digest := sha256.New()
	for {
		digest.Write(chunk.Data)
		if offset+int64(len(chunk.Data)) == size && hex.EncodeToString(digest.Sum(nil)) != checksum {
			if offset == 0 {
				http.Error(w, "Backup checksum did not verify", 503)
			}
			return
		}
		if _, err = w.Write(chunk.Data); err != nil {
			return
		}
		offset += int64(len(chunk.Data))
		if offset == size {
			return
		}
		chunk, err = reader.ReadBackupFor(r.Context(), user, id, offset, limit)
		if err != nil || chunk.BackupID != id || chunk.Offset != offset || chunk.Size != size || chunk.SHA256 != checksum || len(chunk.Data) == 0 || len(chunk.Data) > limit || int64(len(chunk.Data)) > size-offset {
			return
		}
	}
}
