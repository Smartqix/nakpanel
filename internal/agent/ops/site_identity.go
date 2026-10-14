package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var ErrSiteIdentityRemoved = errors.New("website identity has been removed or is being removed")
var ErrSiteIdentityUnknown = errors.New("website identity must first be reconciled from current intent")

type SiteIdentityRegistry struct{ root string }
type siteIdentityRecord struct {
	Identity    types.SiteIdentity `json:"identity"`
	State       string             `json:"state"`
	OperationID int64              `json:"operation_id,omitempty"`
	Revision    int64              `json:"revision,omitempty"`
	RemovalKind string             `json:"removal_kind,omitempty"`
}
type domainIdentityRecord struct {
	ActiveID       int64 `json:"active_id"`
	RemovedHistory bool  `json:"removed_history"`
}
type siteLeaseContextKey struct{}
type siteLease struct {
	registry   string
	identities map[string]types.SiteIdentity
}

func NewSiteIdentityRegistry(root string) *SiteIdentityRegistry {
	if root == "" {
		root = "/var/lib/nakpanel-agent/sites"
	}
	return &SiteIdentityRegistry{root: filepath.Clean(root)}
}

func (r *SiteIdentityRegistry) Initialize() error { return r.ensureRoot() }
func (r *SiteIdentityRegistry) WithSites(ctx context.Context, identities []types.SiteIdentity, fn func(context.Context) error) error {
	return r.withSites(ctx, identities, "existing", 0, 0, fn)
}
func (r *SiteIdentityRegistry) WithCreation(ctx context.Context, identities []types.SiteIdentity, fn func(context.Context) error) error {
	return r.withSites(ctx, identities, "create", 0, 0, fn)
}
func (r *SiteIdentityRegistry) WithRemoval(ctx context.Context, op, revision int64, identities []types.SiteIdentity, fn func(context.Context) error) error {
	return r.withSites(ctx, identities, "remove", op, revision, fn)
}

func (r *SiteIdentityRegistry) withSites(ctx context.Context, identities []types.SiteIdentity, mode string, op, revision int64, fn func(context.Context) error) error {
	if r == nil || fn == nil {
		return errors.New("website identity registry is not configured")
	}
	if err := r.ensureRoot(); err != nil {
		return err
	}
	values := append([]types.SiteIdentity(nil), identities...)
	if lease, ok := ctx.Value(siteLeaseContextKey{}).(siteLease); ok && lease.registry == r.root {
		for _, id := range values {
			held, ok := lease.identities[id.Domain]
			if !ok || !compatibleIdentity(held, id) {
				return errors.New("nested website identity lease expands its scope")
			}
		}
		return fn(ctx)
	}
	locks := []string{}
	resolved := map[string]types.SiteIdentity{}
	for index, id := range values {
		if site.ValidateDomain(id.Domain) != nil || site.NormalizeDomain(id.Domain) != id.Domain || id.SiteID < 0 || id.SubscriptionID < 0 {
			return errors.New("invalid website identity")
		}
		if id.Username != "" && site.ValidateUsername(id.Username) != nil {
			return errors.New("invalid website account identity")
		}
		if id.SiteID > 0 {
			record, err := r.readSite(id.SiteID)
			if err == nil {
				if !compatibleIdentity(record.Identity, id) {
					return errors.New("website identity differs from its registered owner")
				}
				id = record.Identity
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if previous, ok := resolved[id.Domain]; ok {
			if (previous.SiteID > 0 && id.SiteID > 0 && previous.SiteID != id.SiteID) || (previous.SubscriptionID > 0 && id.SubscriptionID > 0 && previous.SubscriptionID != id.SubscriptionID) || (previous.Username != "" && id.Username != "" && previous.Username != id.Username) {
				return errors.New("conflicting website identities")
			}
			merged := id
			if merged.SiteID == 0 {
				merged.SiteID = previous.SiteID
			}
			if merged.SubscriptionID == 0 {
				merged.SubscriptionID = previous.SubscriptionID
			}
			if merged.Username == "" {
				merged.Username = previous.Username
			}
			resolved[id.Domain] = merged
		} else {
			resolved[id.Domain] = id
		}
		values[index] = id
		if id.SubscriptionID > 0 {
			locks = append(locks, fmt.Sprintf("0-sub-%020d", id.SubscriptionID))
		}
		locks = append(locks, "1-domain-"+domainIdentityKey(id.Domain))
		if id.SiteID > 0 {
			locks = append(locks, fmt.Sprintf("2-site-%020d", id.SiteID))
		}
	}
	slices.Sort(locks)
	locks = slices.Compact(locks)
	files := []*os.File{}
	defer func() {
		for index := len(files) - 1; index >= 0; index-- {
			unlockSiteIdentityFile(files[index])
			files[index].Close()
		}
	}()
	for _, key := range locks {
		file, err := openSiteIdentityLock(filepath.Join(r.root, key+".lock"))
		if err != nil {
			return err
		}
		files = append(files, file)
		for {
			err = lockSiteIdentityFile(file)
			if err == nil {
				break
			}
			if !siteIdentityLockBusy(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	for _, id := range values {
		if err := r.validateLease(id, mode, op, revision); err != nil {
			return err
		}
	}
	return fn(context.WithValue(ctx, siteLeaseContextKey{}, siteLease{registry: r.root, identities: resolved}))
}
func compatibleIdentity(stored, supplied types.SiteIdentity) bool {
	return stored.Domain == supplied.Domain && (supplied.SiteID == 0 || stored.SiteID == supplied.SiteID) && (supplied.SubscriptionID == 0 || stored.SubscriptionID == supplied.SubscriptionID) && (supplied.Username == "" || stored.Username == supplied.Username)
}
func (r *SiteIdentityRegistry) validateLease(id types.SiteIdentity, mode string, op, revision int64) error {
	binding, err := r.readDomain(id.Domain)
	if errors.Is(err, os.ErrNotExist) {
		binding = domainIdentityRecord{}
		err = nil
	}
	if err != nil {
		return err
	}
	if id.SiteID == 0 {
		if binding.RemovedHistory {
			return ErrSiteIdentityRemoved
		}
		if binding.ActiveID > 0 {
			record, err := r.readSite(binding.ActiveID)
			if err != nil {
				return err
			}
			if record.State != "active" {
				return ErrSiteIdentityRemoved
			}
			if !compatibleIdentity(record.Identity, id) {
				return errors.New("legacy website account differs from registered identity")
			}
		}
		return nil
	}
	record, err := r.readSite(id.SiteID)
	if errors.Is(err, os.ErrNotExist) {
		if mode != "create" && mode != "remove" && mode != "account-remove" {
			return ErrSiteIdentityUnknown
		}
		if id.SubscriptionID <= 0 || id.Username == "" {
			return errors.New("new website identity requires subscription and account")
		}
		if binding.ActiveID != 0 && binding.ActiveID != id.SiteID {
			return errors.New("hostname is still reserved by another website")
		}
		record = siteIdentityRecord{Identity: id, State: "active"}
		if err = r.writeSite(record); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if !compatibleIdentity(record.Identity, id) {
		return errors.New("website identity differs from its registered owner")
	}
	if record.State != "active" {
		kind := "site"
		if mode == "account-remove" {
			kind = "account"
		}
		if (mode != "remove" && mode != "account-remove") || record.OperationID != op || revision < record.Revision || removalRecordKind(record) != kind {
			return ErrSiteIdentityRemoved
		}
		// Completed old cleanup does not inspect or claim a replacement hostname.
		return nil
	}
	if binding.ActiveID != 0 && binding.ActiveID != id.SiteID {
		return errors.New("hostname is reserved by another website")
	}
	if binding.ActiveID == 0 {
		if mode != "create" && mode != "remove" && mode != "account-remove" {
			return ErrSiteIdentityUnknown
		}
		binding.ActiveID = id.SiteID
		if err = r.writeDomain(id.Domain, binding); err != nil {
			return err
		}
	}
	return nil
}

func (r *SiteIdentityRegistry) MarkRemoved(ctx context.Context, op, revision int64, ids []types.SiteIdentity) error {
	if op <= 0 || revision <= 0 || len(ids) == 0 {
		return errors.New("valid website removal identity is required")
	}
	return r.WithRemoval(ctx, op, revision, ids, func(context.Context) error {
		for _, id := range ids {
			record, err := r.readSite(id.SiteID)
			if err != nil {
				return err
			}
			if record.State != "active" && (record.OperationID != op || revision < record.Revision || removalRecordKind(record) != "site") {
				return ErrSiteIdentityRemoved
			}
			if record.State == "removed" {
				continue
			}
			record.State = "removing"
			record.OperationID = op
			record.RemovalKind = "site"
			record.Revision = revision
			if err = r.writeSite(record); err != nil {
				return err
			}
			binding, err := r.readDomain(id.Domain)
			if err != nil {
				return err
			}
			binding.RemovedHistory = true
			if err = r.writeDomain(id.Domain, binding); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r *SiteIdentityRegistry) CompleteRemoval(ctx context.Context, op int64, ids []types.SiteIdentity) error {
	return r.WithRemoval(ctx, op, 1<<62, ids, func(context.Context) error {
		for _, id := range ids {
			record, err := r.readSite(id.SiteID)
			if err != nil {
				return err
			}
			if record.OperationID != op || record.State == "active" {
				return errors.New("website cleanup was not reserved")
			}
			if record.State != "removed" {
				record.State = "removed"
				if err = r.writeSite(record); err != nil {
					return err
				}
			}
		}
		return r.releaseRemovedBindings(ids)
	})
}

func removalRecordKind(record siteIdentityRecord) string {
	if record.RemovalKind == "" {
		return "site"
	}
	return record.RemovalKind
}
func (r *SiteIdentityRegistry) releaseRemovedBindings(ids []types.SiteIdentity) error {
	for _, id := range ids {
		binding, err := r.readDomain(id.Domain)
		if err != nil {
			return err
		}
		if binding.ActiveID == id.SiteID {
			binding.ActiveID = 0
		}
		binding.RemovedHistory = true
		if err = r.writeDomain(id.Domain, binding); err != nil {
			return err
		}
	}
	return nil
}

// Account teardown uses its own durable namespace. Its replay cannot repeat
// hostname-based cleanup after a different subscription claims that hostname.
func (r *SiteIdentityRegistry) WithAccountRemoval(ctx context.Context, subscriptionID int64, ids []types.SiteIdentity, fn func(context.Context) error) error {
	if subscriptionID <= 0 {
		return errors.New("valid account removal identity is required")
	}
	for _, id := range ids {
		if id.SiteID <= 0 || id.SubscriptionID != subscriptionID {
			return errors.New("account removal has inconsistent website identity")
		}
	}
	return r.withSites(ctx, ids, "account-remove", subscriptionID, 1, func(ctx context.Context) error {
		complete := len(ids) > 0
		for _, id := range ids {
			record, err := r.readSite(id.SiteID)
			if err != nil {
				return err
			}
			if record.State != "removed" {
				complete = false
			}
		}
		if complete {
			return r.releaseRemovedBindings(ids)
		}
		for _, id := range ids {
			record, err := r.readSite(id.SiteID)
			if err != nil {
				return err
			}
			record.State = "removing"
			record.OperationID = subscriptionID
			record.RemovalKind = "account"
			record.Revision = 1
			if err = r.writeSite(record); err != nil {
				return err
			}
			binding, err := r.readDomain(id.Domain)
			if err != nil {
				return err
			}
			binding.RemovedHistory = true
			if err = r.writeDomain(id.Domain, binding); err != nil {
				return err
			}
		}
		if err := fn(ctx); err != nil {
			return err
		}
		for _, id := range ids {
			record, err := r.readSite(id.SiteID)
			if err != nil {
				return err
			}
			record.State = "removed"
			if err = r.writeSite(record); err != nil {
				return err
			}
		}
		return r.releaseRemovedBindings(ids)
	})
}
func (r *SiteIdentityRegistry) Removed(id types.SiteIdentity) (bool, error) {
	if err := r.ensureRoot(); err != nil {
		return false, err
	}
	if id.SiteID > 0 {
		record, err := r.readSite(id.SiteID)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return record.State != "active", nil
	}
	binding, err := r.readDomain(id.Domain)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return binding.RemovedHistory, err
}

func (r *SiteIdentityRegistry) LookupSite(id int64) (types.SiteIdentity, error) {
	if id <= 0 {
		return types.SiteIdentity{}, ErrSiteIdentityUnknown
	}
	record, err := r.readSite(id)
	if err != nil {
		return types.SiteIdentity{}, err
	}
	return record.Identity, nil
}

func domainIdentityKey(domain string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(domain))) }
func (r *SiteIdentityRegistry) ensureRoot() error {
	if !filepath.IsAbs(r.root) {
		return errors.New("website identity root must be absolute")
	}
	info, err := os.Lstat(r.root)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(r.root, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(r.root)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe website identity root")
	}
	if info.Mode().Perm() != 0700 {
		return errors.New("website identity root must have mode 0700")
	}
	if !siteIdentityOwnedByAgent(info) {
		return errors.New("website identity root must be agent-owned")
	}
	parent, err := os.Lstat(filepath.Dir(r.root))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 || !siteIdentityOwnedByAgent(parent) {
		return errors.New("unsafe website identity parent directory")
	}
	return nil
}
func readIdentityFile(path string, out any) error {
	file, err := openSiteIdentityRead(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !siteIdentityOwnedByAgent(info) {
		return errors.New("unsafe website identity record permissions")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("website identity record is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return errors.New("website identity record is invalid")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("website identity record has trailing data")
	}
	return nil
}
func (r *SiteIdentityRegistry) readSite(id int64) (siteIdentityRecord, error) {
	var record siteIdentityRecord
	err := readIdentityFile(filepath.Join(r.root, fmt.Sprintf("site-%d.json", id)), &record)
	if err == nil && (record.Identity.SiteID != id || !slices.Contains([]string{"active", "removing", "removed"}, record.State) || site.ValidateDomain(record.Identity.Domain) != nil) {
		return record, errors.New("website identity record is inconsistent")
	}
	return record, err
}
func (r *SiteIdentityRegistry) readDomain(domain string) (domainIdentityRecord, error) {
	var record domainIdentityRecord
	err := readIdentityFile(filepath.Join(r.root, "domain-"+domainIdentityKey(domain)+".json"), &record)
	return record, err
}
func (r *SiteIdentityRegistry) writeSite(record siteIdentityRecord) error {
	return r.writeRecord(fmt.Sprintf("site-%d.json", record.Identity.SiteID), record)
}
func (r *SiteIdentityRegistry) writeDomain(domain string, record domainIdentityRecord) error {
	return r.writeRecord("domain-"+domainIdentityKey(domain)+".json", record)
}
func (r *SiteIdentityRegistry) writeRecord(name string, value any) error {
	if strings.ContainsAny(name, "/\\") {
		return errors.New("invalid registry record name")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(r.root, name), data, 0600)
}
