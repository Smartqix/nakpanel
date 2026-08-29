package ops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	SecurityStageRoot         = "/var/lib/nakpanel/security-stages"
	securityStageCandidate    = "candidate.conf"
	securityStagePrevious     = "previous.conf"
	securityStageState        = "state.json"
	maxSecurityStageFileBytes = 1 << 20
)

var (
	ErrSecurityStageExists     = errors.New("security stage already exists")
	ErrSecurityStageNotFound   = errors.New("security stage not found")
	ErrSecurityStageExpired    = errors.New("security stage confirmation window expired")
	ErrSecurityStageNotExpired = errors.New("security stage is not due for rollback")
	ErrSecurityStageConfirmed  = errors.New("security stage is already confirmed")
	ErrSecurityStageRolledBack = errors.New("security stage is already rolled back")

	securityOperationIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

type SecurityStageKind string

const (
	SecurityStageNftables SecurityStageKind = "nftables"
	SecurityStageSSH      SecurityStageKind = "ssh"
)

var securityStageTargets = map[SecurityStageKind]string{
	SecurityStageNftables: NftablesConfigPath,
	SecurityStageSSH:      SSHConfigPath,
}

type SecurityStageStatus string

const (
	SecurityStagePending         SecurityStageStatus = "pending_confirmation"
	SecurityStageConfirmedStatus SecurityStageStatus = "confirmed"
	SecurityStageRollbackPending SecurityStageStatus = "rollback_pending"
	SecurityStageRolledBack      SecurityStageStatus = "rolled_back"
)

type SecurityPreviousConfig struct {
	Exists bool
	Data   []byte
}

type SecurityStageRecord struct {
	OperationID    string              `json:"operation_id"`
	Kind           SecurityStageKind   `json:"kind"`
	TargetPath     string              `json:"target_path"`
	Status         SecurityStageStatus `json:"status"`
	CreatedAt      time.Time           `json:"created_at"`
	ConfirmBy      time.Time           `json:"confirm_by"`
	ConfirmedAt    *time.Time          `json:"confirmed_at,omitempty"`
	RolledBackAt   *time.Time          `json:"rolled_back_at,omitempty"`
	CandidateSHA   string              `json:"candidate_sha256"`
	PreviousExists bool                `json:"previous_exists"`
	PreviousSHA    string              `json:"previous_sha256,omitempty"`
}

type SecurityRollbackMaterial struct {
	Record   SecurityStageRecord
	Previous SecurityPreviousConfig
}

type SecurityCandidateMaterial struct {
	Record    SecurityStageRecord
	Candidate []byte
}

type SecurityStageStoreOptions struct {
	Root string
	Now  func() time.Time
}

// SecurityStageStore persists enough state to survive an agent or host restart
// during a firewall or SSH confirmation window. It never accepts a target path;
// the kind-to-path mapping above is the complete privileged registry.
type SecurityStageStore struct {
	root string
	now  func() time.Time
	mu   sync.Mutex
}

func NewSecurityStageStore(opts SecurityStageStoreOptions) *SecurityStageStore {
	root := filepath.Clean(opts.Root)
	if opts.Root == "" {
		root = SecurityStageRoot
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &SecurityStageStore{root: root, now: now}
}

func (s *SecurityStageStore) StageNftables(operationID string, previous SecurityPreviousConfig, policy NftablesPolicy, confirmationWindow time.Duration) (SecurityStageRecord, error) {
	candidate, err := RenderNftablesPolicy(policy)
	if err != nil {
		return SecurityStageRecord{}, err
	}
	return s.stageRendered(SecurityStageNftables, operationID, previous, []byte(candidate), confirmationWindow)
}

func (s *SecurityStageStore) StageSSH(operationID string, previous SecurityPreviousConfig, policy SSHPolicy, confirmationWindow time.Duration) (SecurityStageRecord, error) {
	candidate, err := RenderSSHPolicy(policy)
	if err != nil {
		return SecurityStageRecord{}, err
	}
	return s.stageRendered(SecurityStageSSH, operationID, previous, []byte(candidate), confirmationWindow)
}

func (s *SecurityStageStore) stageRendered(kind SecurityStageKind, operationID string, previous SecurityPreviousConfig, candidate []byte, confirmationWindow time.Duration) (SecurityStageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityStageRecord{}, err
	}
	if confirmationWindow == 0 {
		confirmationWindow = 2 * time.Minute
	}
	if confirmationWindow < 30*time.Second || confirmationWindow > 5*time.Minute {
		return SecurityStageRecord{}, errors.New("security confirmation window must be between 30 seconds and 5 minutes")
	}
	if len(candidate) == 0 || len(candidate) > maxSecurityStageFileBytes {
		return SecurityStageRecord{}, errors.New("rendered security candidate has an invalid size")
	}
	if !previous.Exists && len(previous.Data) != 0 {
		return SecurityStageRecord{}, errors.New("missing previous configuration cannot contain data")
	}
	if len(previous.Data) > maxSecurityStageFileBytes {
		return SecurityStageRecord{}, errors.New("previous security configuration exceeds the size limit")
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityStageRecord{}, err
	}

	stageDir := s.stageDir(kind, operationID)
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return SecurityStageRecord{}, ErrSecurityStageExists
		}
		return SecurityStageRecord{}, fmt.Errorf("create security stage: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageDir)
		}
	}()

	if err := writeExclusiveRegularFile(filepath.Join(stageDir, securityStageCandidate), candidate, 0o600); err != nil {
		return SecurityStageRecord{}, fmt.Errorf("write security candidate: %w", err)
	}
	previousSHA := ""
	if previous.Exists {
		if err := writeExclusiveRegularFile(filepath.Join(stageDir, securityStagePrevious), previous.Data, 0o600); err != nil {
			return SecurityStageRecord{}, fmt.Errorf("write previous security configuration: %w", err)
		}
		previousSHA = sha256Hex(previous.Data)
	}

	now := s.now().UTC()
	record := SecurityStageRecord{
		OperationID: operationID, Kind: kind, TargetPath: securityStageTargets[kind],
		Status: SecurityStagePending, CreatedAt: now, ConfirmBy: now.Add(confirmationWindow),
		CandidateSHA: sha256Hex(candidate), PreviousExists: previous.Exists, PreviousSHA: previousSHA,
	}
	if err := writeSecurityStageRecord(stageDir, record); err != nil {
		return SecurityStageRecord{}, err
	}
	cleanup = false
	return record, nil
}

func (s *SecurityStageStore) Load(kind SecurityStageKind, operationID string) (SecurityStageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityStageRecord{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityStageRecord{}, err
	}
	return s.loadLocked(kind, operationID)
}

// Candidate returns the exact integrity-checked bytes that were staged. An
// applier should use this material instead of re-rendering mutable policy.
func (s *SecurityStageStore) Candidate(kind SecurityStageKind, operationID string) (SecurityCandidateMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityCandidateMaterial{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityCandidateMaterial{}, err
	}
	record, err := s.loadLocked(kind, operationID)
	if err != nil {
		return SecurityCandidateMaterial{}, err
	}
	candidate, err := readRegularFile(filepath.Join(s.stageDir(kind, operationID), securityStageCandidate), maxSecurityStageFileBytes)
	if err != nil {
		return SecurityCandidateMaterial{}, fmt.Errorf("read security candidate: %w", err)
	}
	if sha256Hex(candidate) != record.CandidateSHA {
		return SecurityCandidateMaterial{}, errors.New("security candidate failed its integrity check")
	}
	return SecurityCandidateMaterial{Record: record, Candidate: candidate}, nil
}

func (s *SecurityStageStore) Confirm(kind SecurityStageKind, operationID string) (SecurityStageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityStageRecord{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityStageRecord{}, err
	}
	record, err := s.loadLocked(kind, operationID)
	if err != nil {
		return SecurityStageRecord{}, err
	}
	switch record.Status {
	case SecurityStageConfirmedStatus:
		return record, nil
	case SecurityStageRolledBack, SecurityStageRollbackPending:
		return SecurityStageRecord{}, ErrSecurityStageRolledBack
	case SecurityStagePending:
	default:
		return SecurityStageRecord{}, fmt.Errorf("security stage has invalid status %q", record.Status)
	}
	if !s.now().UTC().Before(record.ConfirmBy) {
		return SecurityStageRecord{}, ErrSecurityStageExpired
	}
	now := s.now().UTC()
	record.Status = SecurityStageConfirmedStatus
	record.ConfirmedAt = &now
	if err := writeSecurityStageRecord(s.stageDir(kind, operationID), record); err != nil {
		return SecurityStageRecord{}, err
	}
	return record, nil
}

// BeginRollback is retryable. Once the deadline passes it returns the exact
// previous material until CompleteRollback records successful restoration.
func (s *SecurityStageStore) BeginRollback(kind SecurityStageKind, operationID string) (SecurityRollbackMaterial, error) {
	return s.beginRollback(kind, operationID, false)
}

// ForceRollback starts an operator-requested rollback without waiting for the
// confirmation deadline. It remains retryable and uses the same integrity
// checked previous material as automatic recovery.
func (s *SecurityStageStore) ForceRollback(kind SecurityStageKind, operationID string) (SecurityRollbackMaterial, error) {
	return s.beginRollback(kind, operationID, true)
}

func (s *SecurityStageStore) beginRollback(kind SecurityStageKind, operationID string, force bool) (SecurityRollbackMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityRollbackMaterial{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityRollbackMaterial{}, err
	}
	record, err := s.loadLocked(kind, operationID)
	if err != nil {
		return SecurityRollbackMaterial{}, err
	}
	switch record.Status {
	case SecurityStageConfirmedStatus:
		return SecurityRollbackMaterial{}, ErrSecurityStageConfirmed
	case SecurityStageRolledBack:
		return SecurityRollbackMaterial{}, ErrSecurityStageRolledBack
	case SecurityStagePending:
		if !force && s.now().UTC().Before(record.ConfirmBy) {
			return SecurityRollbackMaterial{}, ErrSecurityStageNotExpired
		}
		record.Status = SecurityStageRollbackPending
		if err := writeSecurityStageRecord(s.stageDir(kind, operationID), record); err != nil {
			return SecurityRollbackMaterial{}, err
		}
	case SecurityStageRollbackPending:
	default:
		return SecurityRollbackMaterial{}, fmt.Errorf("security stage has invalid status %q", record.Status)
	}

	previous := SecurityPreviousConfig{Exists: record.PreviousExists}
	if record.PreviousExists {
		data, err := readRegularFile(filepath.Join(s.stageDir(kind, operationID), securityStagePrevious), maxSecurityStageFileBytes)
		if err != nil {
			return SecurityRollbackMaterial{}, fmt.Errorf("read previous security configuration: %w", err)
		}
		if sha256Hex(data) != record.PreviousSHA {
			return SecurityRollbackMaterial{}, errors.New("previous security configuration failed its integrity check")
		}
		previous.Data = data
	}
	return SecurityRollbackMaterial{Record: record, Previous: previous}, nil
}

func (s *SecurityStageStore) CompleteRollback(kind SecurityStageKind, operationID string) (SecurityStageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSecurityStageIdentity(kind, operationID); err != nil {
		return SecurityStageRecord{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return SecurityStageRecord{}, err
	}
	record, err := s.loadLocked(kind, operationID)
	if err != nil {
		return SecurityStageRecord{}, err
	}
	if record.Status == SecurityStageRolledBack {
		return record, nil
	}
	if record.Status != SecurityStageRollbackPending {
		return SecurityStageRecord{}, errors.New("security stage rollback has not begun")
	}
	now := s.now().UTC()
	record.Status = SecurityStageRolledBack
	record.RolledBackAt = &now
	if err := writeSecurityStageRecord(s.stageDir(kind, operationID), record); err != nil {
		return SecurityStageRecord{}, err
	}
	return record, nil
}

// RollbacksDue lets startup recovery find both newly expired changes and
// rollbacks interrupted after BeginRollback.
func (s *SecurityStageStore) RollbacksDue() ([]SecurityStageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list security stages: %w", err)
	}
	now := s.now().UTC()
	var records []SecurityStageRecord
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, fmt.Errorf("unsafe entry %q in security stage root", entry.Name())
		}
		record, err := readSecurityStageRecord(filepath.Join(s.root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if err := validateSecurityStageRecord(record); err != nil {
			return nil, err
		}
		if filepath.Base(s.stageDir(record.Kind, record.OperationID)) != entry.Name() {
			return nil, fmt.Errorf("security stage directory %q does not match its record", entry.Name())
		}
		if record.Status == SecurityStageRollbackPending ||
			(record.Status == SecurityStagePending && !now.Before(record.ConfirmBy)) {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].ConfirmBy.Equal(records[j].ConfirmBy) {
			return records[i].OperationID < records[j].OperationID
		}
		return records[i].ConfirmBy.Before(records[j].ConfirmBy)
	})
	return records, nil
}

func (s *SecurityStageStore) loadLocked(kind SecurityStageKind, operationID string) (SecurityStageRecord, error) {
	stageDir := s.stageDir(kind, operationID)
	info, err := os.Lstat(stageDir)
	if errors.Is(err, os.ErrNotExist) {
		return SecurityStageRecord{}, ErrSecurityStageNotFound
	}
	if err != nil {
		return SecurityStageRecord{}, fmt.Errorf("inspect security stage: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return SecurityStageRecord{}, errors.New("security stage path is not a real directory")
	}
	record, err := readSecurityStageRecord(stageDir)
	if err != nil {
		return SecurityStageRecord{}, err
	}
	if err := validateSecurityStageRecord(record); err != nil {
		return SecurityStageRecord{}, err
	}
	if record.Kind != kind || record.OperationID != operationID {
		return SecurityStageRecord{}, errors.New("security stage identity does not match its path")
	}
	candidate, err := readRegularFile(filepath.Join(stageDir, securityStageCandidate), maxSecurityStageFileBytes)
	if err != nil {
		return SecurityStageRecord{}, fmt.Errorf("read security candidate: %w", err)
	}
	if sha256Hex(candidate) != record.CandidateSHA {
		return SecurityStageRecord{}, errors.New("security candidate failed its integrity check")
	}
	if record.PreviousExists {
		previous, err := readRegularFile(filepath.Join(stageDir, securityStagePrevious), maxSecurityStageFileBytes)
		if err != nil {
			return SecurityStageRecord{}, fmt.Errorf("read previous security configuration: %w", err)
		}
		if sha256Hex(previous) != record.PreviousSHA {
			return SecurityStageRecord{}, errors.New("previous security configuration failed its integrity check")
		}
	} else if _, err := os.Lstat(filepath.Join(stageDir, securityStagePrevious)); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return SecurityStageRecord{}, errors.New("unexpected previous configuration in security stage")
		}
		return SecurityStageRecord{}, fmt.Errorf("inspect previous security configuration: %w", err)
	}
	return record, nil
}

func (s *SecurityStageStore) ensureRoot() error {
	if !filepath.IsAbs(s.root) || s.root == string(filepath.Separator) {
		return errors.New("security stage root must be an absolute non-root path")
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create security stage root: %w", err)
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("inspect security stage root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("security stage root is not a real directory")
	}
	if err := os.Chmod(s.root, 0o700); err != nil {
		return fmt.Errorf("secure security stage root: %w", err)
	}
	return nil
}

func (s *SecurityStageStore) stageDir(kind SecurityStageKind, operationID string) string {
	return filepath.Join(s.root, string(kind)+"-"+operationID)
}

func validateSecurityStageIdentity(kind SecurityStageKind, operationID string) error {
	if _, exists := securityStageTargets[kind]; !exists {
		return fmt.Errorf("security stage kind %q is not managed by Nakpanel", kind)
	}
	if !securityOperationIDRE.MatchString(operationID) {
		return errors.New("security operation id is invalid")
	}
	return nil
}

func validateSecurityStageRecord(record SecurityStageRecord) error {
	if err := validateSecurityStageIdentity(record.Kind, record.OperationID); err != nil {
		return err
	}
	if record.TargetPath != securityStageTargets[record.Kind] {
		return errors.New("security stage target does not match the fixed registry")
	}
	switch record.Status {
	case SecurityStagePending, SecurityStageConfirmedStatus, SecurityStageRollbackPending, SecurityStageRolledBack:
	default:
		return fmt.Errorf("security stage has invalid status %q", record.Status)
	}
	if record.CreatedAt.IsZero() || record.ConfirmBy.IsZero() || !record.ConfirmBy.After(record.CreatedAt) {
		return errors.New("security stage has an invalid confirmation window")
	}
	if !validSHA256Hex(record.CandidateSHA) {
		return errors.New("security stage has an invalid candidate digest")
	}
	if record.PreviousExists != validSHA256Hex(record.PreviousSHA) {
		return errors.New("security stage has inconsistent previous configuration metadata")
	}
	return nil
}

func writeSecurityStageRecord(stageDir string, record SecurityStageRecord) error {
	info, err := os.Lstat(stageDir)
	if err != nil {
		return fmt.Errorf("inspect security stage directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("security stage directory is unsafe")
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode security stage record: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(filepath.Join(stageDir, securityStageState), data, 0o600); err != nil {
		return fmt.Errorf("write security stage record: %w", err)
	}
	return nil
}

func readSecurityStageRecord(stageDir string) (SecurityStageRecord, error) {
	data, err := readRegularFile(filepath.Join(stageDir, securityStageState), 64<<10)
	if err != nil {
		return SecurityStageRecord{}, fmt.Errorf("read security stage record: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record SecurityStageRecord
	if err := decoder.Decode(&record); err != nil {
		return SecurityStageRecord{}, fmt.Errorf("decode security stage record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SecurityStageRecord{}, errors.New("security stage record contains trailing data")
	}
	return record, nil
}

func writeExclusiveRegularFile(path string, data []byte, mode os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return file.Chmod(mode)
}

func readRegularFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
