package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type WordPressDatabaseState struct {
	DatabasePresent bool
	UserPresent     bool
}

type WordPressDatabaseRemover interface {
	Inspect(context.Context, int64, string, string) (WordPressDatabaseState, error)
	Remove(context.Context, int64, string, string) (WordPressDatabaseState, error)
}

type wordpressRemovalMarker struct {
	OperationID      int64 `json:"operation_id"`
	InstanceID       int64 `json:"instance_id"`
	DesiredRevision  int64 `json:"desired_revision"`
	FilesQuarantined bool  `json:"files_quarantined"`
	DatabaseRemoved  bool  `json:"database_removed"`
}

type mariaDBWordPressRemover struct {
	db *sql.DB
}

func NewMariaDBWordPressRemover(db *sql.DB) WordPressDatabaseRemover {
	return &mariaDBWordPressRemover{db: db}
}

type lazyMariaDBWordPressRemover struct {
	dsn string
}

func NewLazyMariaDBWordPressRemover(dsn string) WordPressDatabaseRemover {
	if strings.TrimSpace(dsn) == "" {
		dsn = DefaultMariaDBDSN()
	}
	return &lazyMariaDBWordPressRemover{dsn: dsn}
}

func (r *lazyMariaDBWordPressRemover) open(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("mysql", r.dsn)
	if err != nil {
		return nil, fmt.Errorf("open MariaDB connection: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping MariaDB connection: %w", err)
	}
	return db, nil
}

func (r *lazyMariaDBWordPressRemover) Inspect(ctx context.Context, siteID int64, databaseName, databaseUser string) (WordPressDatabaseState, error) {
	db, err := r.open(ctx)
	if err != nil {
		return WordPressDatabaseState{}, err
	}
	defer db.Close()
	return NewMariaDBWordPressRemover(db).Inspect(ctx, siteID, databaseName, databaseUser)
}

func (r *lazyMariaDBWordPressRemover) Remove(ctx context.Context, siteID int64, databaseName, databaseUser string) (WordPressDatabaseState, error) {
	db, err := r.open(ctx)
	if err != nil {
		return WordPressDatabaseState{}, err
	}
	defer db.Close()
	return NewMariaDBWordPressRemover(db).Remove(ctx, siteID, databaseName, databaseUser)
}

func validateWordPressDatabaseIdentity(siteID int64, databaseName, databaseUser string) error {
	if siteID <= 0 {
		return errors.New("valid WordPress site ID is required")
	}
	databasePattern := regexp.MustCompile(fmt.Sprintf(`^wp_s%d_[a-f0-9]{8}$`, siteID))
	userPattern := regexp.MustCompile(fmt.Sprintf(`^wp_u%d_[a-f0-9]{8}$`, siteID))
	if !databasePattern.MatchString(databaseName) || !userPattern.MatchString(databaseUser) {
		return errors.New("invalid Toolkit-managed WordPress database identity")
	}
	return nil
}

func (r *mariaDBWordPressRemover) Inspect(ctx context.Context, siteID int64, databaseName, databaseUser string) (WordPressDatabaseState, error) {
	if r == nil || r.db == nil {
		return WordPressDatabaseState{}, errors.New("MariaDB connection is unavailable")
	}
	if err := validateWordPressDatabaseIdentity(siteID, databaseName, databaseUser); err != nil {
		return WordPressDatabaseState{}, err
	}
	var state WordPressDatabaseState
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?)`, databaseName).Scan(&state.DatabasePresent); err != nil {
		return state, fmt.Errorf("inspect WordPress database: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mysql.user WHERE User=? AND Host='localhost')`, databaseUser).Scan(&state.UserPresent); err != nil {
		return state, fmt.Errorf("inspect WordPress database user: %w", err)
	}
	return state, nil
}

func (r *mariaDBWordPressRemover) Remove(ctx context.Context, siteID int64, databaseName, databaseUser string) (WordPressDatabaseState, error) {
	state, err := r.Inspect(ctx, siteID, databaseName, databaseUser)
	if err != nil {
		return state, err
	}
	if state.DatabasePresent {
		if _, err = r.db.ExecContext(ctx, "DROP DATABASE "+quoteMariaDBIdentifier(databaseName)); err != nil {
			return state, fmt.Errorf("drop database: %w", err)
		}
		state.DatabasePresent = false
	}
	if state.UserPresent {
		if _, err = r.db.ExecContext(ctx, "DROP USER "+quoteMariaDBAccount(databaseUser)); err != nil {
			return state, fmt.Errorf("drop database user: %w", err)
		}
		state.UserPresent = false
	}
	return state, nil
}

func (p *WordPressProvisioner) removalDocumentRoot(spec types.WordPressSiteSpec) (string, error) {
	if spec.InstanceID <= 0 || spec.SubscriptionID <= 0 || spec.SiteID <= 0 || spec.DesiredRevision <= 0 ||
		site.ValidateUsername(spec.Username) != nil || site.ValidateDomain(spec.Domain) != nil ||
		!phpVersionRE.MatchString(spec.PHPVersion) || spec.HostingMode != types.PHPHostingModeClassic {
		return "", errors.New("validated Classic WordPress site identity is required")
	}
	domainRoot := filepath.Join(p.homeRoot, spec.Username, "domains", spec.Domain)
	root := filepath.Join(domainRoot, "public_html")
	if !pathWithin(domainRoot, root) {
		return "", errors.New("invalid WordPress removal root")
	}
	return root, nil
}

func recognizedWordPressRoot(homeRoot, root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("WordPress document root must be a real directory")
	}
	if err = validateManagedDirectoryPath(homeRoot, root); err != nil {
		return fmt.Errorf("unsafe WordPress document root: %w", err)
	}
	loadInfo, err := os.Lstat(filepath.Join(root, "wp-load.php"))
	if err != nil || !loadInfo.Mode().IsRegular() || loadInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("recognized WordPress wp-load.php was not found")
	}
	config, err := readWordPressConfig(filepath.Join(root, "wp-config.php"))
	if err != nil {
		return errors.New("recognized WordPress configuration was not found")
	}
	text := string(config)
	if !strings.Contains(text, "DB_NAME") || !strings.Contains(text, "ABSPATH") || !strings.Contains(text, "wp-settings.php") {
		return errors.New("document root is not a recognized WordPress installation")
	}
	return nil
}

func wordpressRemovalPaths(root string, operationID int64) (stateDir, markerPath, quarantine, candidate string) {
	domainRoot := filepath.Dir(root)
	stateDir = filepath.Join(domainRoot, ".nakpanel", "wordpress-removals")
	markerPath = filepath.Join(stateDir, fmt.Sprintf("operation-%d.json", operationID))
	quarantine = filepath.Join(domainRoot, fmt.Sprintf(".nakpanel-wordpress-removed-%d", operationID))
	candidate = filepath.Join(domainRoot, fmt.Sprintf(".nakpanel-wordpress-placeholder-%d", operationID))
	return
}

func loadWordPressRemovalMarker(path string) (wordpressRemovalMarker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wordpressRemovalMarker{}, err
	}
	var marker wordpressRemovalMarker
	if err = json.Unmarshal(data, &marker); err != nil {
		return marker, errors.New("invalid WordPress removal marker")
	}
	return marker, nil
}

func writeWordPressRemovalMarker(stateDir, path string, marker wordpressRemovalMarker) error {
	domainRoot := filepath.Dir(filepath.Dir(stateDir))
	if err := ensureNoSymlinkComponents(domainRoot, stateDir); err != nil {
		return fmt.Errorf("validate WordPress removal state directory: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := ensureNoSymlinkComponents(domainRoot, stateDir); err != nil {
		return fmt.Errorf("validate created WordPress removal state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(stateDir, ".marker-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDir(stateDir)
}

func markerMatchesRequest(marker wordpressRemovalMarker, req types.WordPressOperationReq) bool {
	return marker.OperationID == req.OperationID && marker.InstanceID == req.Site.InstanceID && marker.DesiredRevision == req.Site.DesiredRevision
}

func (p *WordPressProvisioner) prepareRemovalPlaceholder(req types.WordPressOperationReq, candidate string) error {
	if err := p.prepareWordPressStage(req.Site.Username, candidate); err != nil {
		return err
	}
	if err := p.writeAccountFile(req.Site.Username, filepath.Join(candidate, "index.php"), []byte(renderPlaceholderIndex(SitePlan{Domain: req.Site.Domain})), 0o640); err != nil {
		return err
	}
	if err := secureHostedDocumentTree(candidate); err != nil {
		return fmt.Errorf("secure WordPress removal placeholder: %w", err)
	}
	return syncDir(candidate)
}

func rollbackWordPressQuarantine(root, quarantine string, req types.WordPressOperationReq) error {
	entries, err := os.ReadDir(root)
	if err != nil || !isNakpanelPlaceholderDocumentRoot(root, req.Site.Domain, entries) {
		return errors.New("refusing to roll back an unrecognized placeholder")
	}
	if err = os.RemoveAll(root); err != nil {
		return err
	}
	if err = os.Rename(quarantine, root); err != nil {
		return err
	}
	return syncDir(filepath.Dir(root))
}

func (p *WordPressProvisioner) uninstallWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	if req.OperationID <= 0 || req.Removal == nil {
		return types.WordPressOperationResult{}, errors.New("WordPress removal specification is required")
	}
	root, err := p.removalDocumentRoot(req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	stateDir, markerPath, quarantine, candidate := wordpressRemovalPaths(root, req.OperationID)
	marker, markerErr := loadWordPressRemovalMarker(markerPath)
	switch {
	case markerErr == nil:
		if !markerMatchesRequest(marker, req) {
			return types.WordPressOperationResult{}, errors.New("WordPress removal marker does not match the requested revision")
		}
	case !errors.Is(markerErr, os.ErrNotExist):
		return types.WordPressOperationResult{}, markerErr
	default:
		if _, statErr := os.Lstat(quarantine); statErr == nil {
			return types.WordPressOperationResult{}, errors.New("unmarked WordPress quarantine requires operator recovery")
		}
		if err = recognizedWordPressRoot(p.homeRoot, root); err != nil {
			return types.WordPressOperationResult{}, err
		}
		if req.Removal.DeleteDatabase {
			if p.databaseRemover == nil {
				return types.WordPressOperationResult{}, errors.New("WordPress database remover is unavailable")
			}
			if err = validateWordPressDatabaseIdentity(req.Site.SiteID, req.Removal.DatabaseName, req.Removal.DatabaseUser); err != nil {
				return types.WordPressOperationResult{}, err
			}
			if _, err = p.databaseRemover.Inspect(ctx, req.Site.SiteID, req.Removal.DatabaseName, req.Removal.DatabaseUser); err != nil {
				return types.WordPressOperationResult{}, err
			}
		}
		marker = wordpressRemovalMarker{OperationID: req.OperationID, InstanceID: req.Site.InstanceID, DesiredRevision: req.Site.DesiredRevision}
		if err = writeWordPressRemovalMarker(stateDir, markerPath, marker); err != nil {
			return types.WordPressOperationResult{}, err
		}
	}
	if !marker.FilesQuarantined {
		if err = p.prepareRemovalPlaceholder(req, candidate); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("prepare WordPress placeholder: %w", err)
		}
		if err = os.Rename(root, quarantine); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("quarantine WordPress document root: %w", err)
		}
		if err = os.Rename(candidate, root); err != nil {
			rollbackErr := os.Rename(quarantine, root)
			return types.WordPressOperationResult{}, errors.Join(fmt.Errorf("activate WordPress placeholder: %w", err), rollbackErr)
		}
		if err = syncDir(filepath.Dir(root)); err != nil {
			return types.WordPressOperationResult{}, err
		}
		marker.FilesQuarantined = true
		if err = writeWordPressRemovalMarker(stateDir, markerPath, marker); err != nil {
			return types.WordPressOperationResult{}, err
		}
	}
	removal := &types.WordPressRemovalResult{FilesRemoved: true, DatabasePreserved: !req.Removal.DeleteDatabase}
	if req.Removal.DeleteDatabase && !marker.DatabaseRemoved {
		state, removeErr := p.databaseRemover.Remove(ctx, req.Site.SiteID, req.Removal.DatabaseName, req.Removal.DatabaseUser)
		if removeErr != nil {
			if state.DatabasePresent {
				rollbackErr := rollbackWordPressQuarantine(root, quarantine, req)
				if rollbackErr == nil {
					marker.FilesQuarantined = false
					_ = writeWordPressRemovalMarker(stateDir, markerPath, marker)
				}
				return types.WordPressOperationResult{}, errors.Join(removeErr, rollbackErr)
			}
			return types.WordPressOperationResult{}, removeErr
		}
		marker.DatabaseRemoved = true
		if err = writeWordPressRemovalMarker(stateDir, markerPath, marker); err != nil {
			return types.WordPressOperationResult{}, err
		}
	}
	removal.DatabaseRemoved = marker.DatabaseRemoved
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Removal: removal, Output: "WordPress removed"}, nil
}

func (p *WordPressProvisioner) finalizeWordPressRemoval(_ context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	if req.OperationID <= 0 || req.Removal == nil {
		return types.WordPressOperationResult{}, errors.New("WordPress removal specification is required")
	}
	root, err := p.removalDocumentRoot(req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	_, markerPath, quarantine, _ := wordpressRemovalPaths(root, req.OperationID)
	marker, err := loadWordPressRemovalMarker(markerPath)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	if !markerMatchesRequest(marker, req) || !marker.FilesQuarantined {
		return types.WordPressOperationResult{}, errors.New("WordPress removal marker does not match the requested revision")
	}
	if err = os.RemoveAll(quarantine); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("finalize WordPress quarantine: %w", err)
	}
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Removal: &types.WordPressRemovalResult{
		FilesRemoved: true, DatabaseRemoved: marker.DatabaseRemoved, DatabasePreserved: !marker.DatabaseRemoved,
	}, Output: "WordPress removal finalized"}, nil
}
