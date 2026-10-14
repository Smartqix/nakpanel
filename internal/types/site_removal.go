package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

const OpTeardownSite = "teardown_site"

type SiteRemovalStage string

const (
	RemovalWaiting      SiteRemovalStage = "waiting"
	RemovalStopServices SiteRemovalStage = "stop_services"
	RemovalHosting      SiteRemovalStage = "remove_hosting"
	RemovalShared       SiteRemovalStage = "reconcile_shared"
	RemovalFinalize     SiteRemovalStage = "finalize"
	RemovalCompleted    SiteRemovalStage = "completed"
)

type SiteRemovalSite struct {
	SiteID         int64  `json:"site_id"`
	SubscriptionID int64  `json:"subscription_id"`
	CustomerID     int64  `json:"customer_id"`
	ParentSiteID   int64  `json:"parent_site_id,omitempty"`
	Username       string `json:"username"`
	Domain         string `json:"domain"`
	PHPVersion     string `json:"php_version"`
}

type SiteRemovalResource struct {
	ID           int64  `json:"id"`
	SiteID       int64  `json:"site_id,omitempty"`
	ParentID     int64  `json:"parent_id,omitempty"`
	Revision     int64  `json:"revision,omitempty"`
	Kind         string `json:"kind"`
	Name         string `json:"name,omitempty"`
	IntentDigest string `json:"intent_digest,omitempty"`
}

type SiteRemovalDatabase struct {
	ID               int64  `json:"id"`
	SiteID           int64  `json:"site_id"`
	SubscriptionID   int64  `json:"subscription_id"`
	Name             string `json:"name"`
	Principal        string `json:"principal"`
	Provenance       string `json:"provenance,omitempty"`
	DeletionEligible bool   `json:"deletion_eligible"`
	IneligibleReason string `json:"ineligible_reason,omitempty"`
	RecoveryBackupID int64  `json:"recovery_backup_id,omitempty"`
}

type SiteRemovalSnapshot struct {
	SchemaVersion int                   `json:"schema_version"`
	Sites         []SiteRemovalSite     `json:"sites"`
	Resources     []SiteRemovalResource `json:"resources,omitempty"`
	Databases     []SiteRemovalDatabase `json:"databases,omitempty"`
	Backups       []SiteRemovalResource `json:"backups,omitempty"`
	Dependencies  []string              `json:"dependencies,omitempty"`
}

func (snapshot SiteRemovalSnapshot) Digest() string {
	snapshot.Sites = append([]SiteRemovalSite(nil), snapshot.Sites...)
	snapshot.Resources = append([]SiteRemovalResource(nil), snapshot.Resources...)
	snapshot.Databases = append([]SiteRemovalDatabase(nil), snapshot.Databases...)
	snapshot.Backups = append([]SiteRemovalResource(nil), snapshot.Backups...)
	snapshot.Dependencies = append([]string(nil), snapshot.Dependencies...)
	sort.Slice(snapshot.Sites, func(i, j int) bool { return snapshot.Sites[i].SiteID < snapshot.Sites[j].SiteID })
	sort.Slice(snapshot.Databases, func(i, j int) bool { return snapshot.Databases[i].ID < snapshot.Databases[j].ID })
	for _, refs := range [][]SiteRemovalResource{snapshot.Resources, snapshot.Backups} {
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Kind != refs[j].Kind {
				return refs[i].Kind < refs[j].Kind
			}
			if refs[i].ID != refs[j].ID {
				return refs[i].ID < refs[j].ID
			}
			if refs[i].SiteID != refs[j].SiteID {
				return refs[i].SiteID < refs[j].SiteID
			}
			if refs[i].ParentID != refs[j].ParentID {
				return refs[i].ParentID < refs[j].ParentID
			}
			if refs[i].Name != refs[j].Name {
				return refs[i].Name < refs[j].Name
			}
			if refs[i].Revision != refs[j].Revision {
				return refs[i].Revision < refs[j].Revision
			}
			return refs[i].IntentDigest < refs[j].IntentDigest
		})
	}
	sort.Strings(snapshot.Dependencies)
	data, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type SiteRemovalPreview struct {
	SiteID                       int64                 `json:"site_id"`
	SubscriptionID               int64                 `json:"subscription_id"`
	CustomerID                   int64                 `json:"customer_id"`
	ParentSiteID                 int64                 `json:"parent_site_id,omitempty"`
	PrimarySiteID                int64                 `json:"primary_site_id,omitempty"`
	Domain                       string                `json:"domain"`
	Kind                         string                `json:"kind"`
	Allowed                      bool                  `json:"allowed"`
	RequiresHostnameConfirmation bool                  `json:"requires_hostname_confirmation"`
	BlockedReasons               []string              `json:"blocked_reasons,omitempty"`
	Snapshot                     SiteRemovalSnapshot   `json:"snapshot"`
	Digest                       string                `json:"digest"`
	Operation                    *SiteRemovalOperation `json:"operation,omitempty"`
}

type RemoveSiteReq struct {
	SiteID               int64   `json:"site_id"`
	RequestID            string  `json:"request_id"`
	PreviewDigest        string  `json:"preview_digest"`
	ConfirmDomain        string  `json:"confirm_domain"`
	AcknowledgePermanent bool    `json:"acknowledge_permanent"`
	IncludeChildren      bool    `json:"include_children"`
	DeleteDatabaseIDs    []int64 `json:"delete_database_ids,omitempty"`
}

type SiteRemovalOperation struct {
	ID                int64               `json:"id"`
	RequestID         string              `json:"request_id"`
	SiteID            int64               `json:"site_id"`
	SubscriptionID    int64               `json:"subscription_id"`
	CustomerID        int64               `json:"customer_id"`
	ActorUserID       int64               `json:"actor_user_id,omitempty"`
	ActorLabel        string              `json:"actor_label"`
	Domain            string              `json:"domain"`
	ParentSiteID      int64               `json:"parent_site_id,omitempty"`
	Snapshot          SiteRemovalSnapshot `json:"snapshot"`
	DeleteDatabaseIDs []int64             `json:"delete_database_ids,omitempty"`
	Revision          int64               `json:"revision"`
	State             string              `json:"state"`
	Stage             SiteRemovalStage    `json:"stage"`
	Checkpoints       []string            `json:"checkpoints,omitempty"`
	LastError         string              `json:"last_error,omitempty"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	CompletedAt       *time.Time          `json:"completed_at,omitempty"`
}

type TeardownSiteReq struct {
	OperationID       int64               `json:"operation_id"`
	Revision          int64               `json:"revision"`
	SubscriptionID    int64               `json:"subscription_id"`
	Snapshot          SiteRemovalSnapshot `json:"snapshot"`
	Stage             SiteRemovalStage    `json:"stage"`
	DeleteDatabaseIDs []int64             `json:"delete_database_ids,omitempty"`
}
type TeardownSiteResult struct {
	OperationID int64    `json:"operation_id"`
	Revision    int64    `json:"revision"`
	Checkpoints []string `json:"checkpoints"`
}
