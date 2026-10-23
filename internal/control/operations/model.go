// Package operations owns durable operational state and its authorization rules.
// Provisioning workers retain responsibility for actual resource mutations.
package operations

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("operation resource not found")
	ErrConflict = errors.New("operation state conflict")
	ErrInvalid  = errors.New("invalid operation input")
)

type ResourceKind string

const (
	ResourceServer       ResourceKind = "server"
	ResourceSite         ResourceKind = "site"
	ResourceSubscription ResourceKind = "subscription"
	ResourceCustomer     ResourceKind = "customer"
	ResourceUser         ResourceKind = "user"
)

type Resource struct {
	Kind ResourceKind `json:"kind"`
	ID   int64        `json:"id"`
}

func (r Resource) Valid() bool {
	switch r.Kind {
	case ResourceServer:
		return r.ID == 0
	case ResourceSite, ResourceSubscription, ResourceCustomer, ResourceUser:
		return r.ID > 0
	default:
		return false
	}
}

type State string

const (
	StateQueued       State = "queued"
	StateRunning      State = "running"
	StateWaitingRetry State = "waiting_retry"
	StateSucceeded    State = "succeeded"
	StateFailed       State = "failed"
	StateCancelled    State = "cancelled"
)

func (s State) Terminal() bool { return s == StateSucceeded || s == StateFailed || s == StateCancelled }

type Operation struct {
	Target         string    `json:"target"`
	ID             int64     `json:"id"`
	Kind           string    `json:"kind"`
	Resource       Resource  `json:"resource"`
	Title          string    `json:"title"`
	Trigger        string    `json:"trigger"`
	State          State     `json:"state"`
	Stage          string    `json:"stage"`
	IntentRevision int64     `json:"intent_revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type NewOperation struct {
	Key, Kind, Title, Trigger string
	Resource                  Resource
	IntentRevision            int64
}
type Attempt struct {
	ID          int64      `json:"id"`
	OperationID int64      `json:"operation_id"`
	Number      int        `json:"number"`
	RiverJobID  int64      `json:"-"`
	State       State      `json:"state"`
	ErrorCode   string     `json:"error_code,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}
type Issue struct {
	Target          string               `json:"target"`
	ID              int64                `json:"id"`
	Resource        Resource             `json:"resource"`
	Kind            string               `json:"kind"`
	Condition       string               `json:"condition"`
	Severity        string               `json:"severity"`
	Title           string               `json:"title"`
	Summary         string               `json:"summary"`
	State           string               `json:"state"`
	Generation      int64                `json:"generation"`
	Occurrences     int                  `json:"occurrences"`
	LatestEventID   int64                `json:"-"`
	IntentRevision  int64                `json:"intent_revision"`
	OperationID     int64                `json:"operation_id,omitempty"`
	ObservedAt      time.Time            `json:"observed_at"`
	AcknowledgedAt  *time.Time           `json:"acknowledged_at,omitempty"`
	ResolvedAt      *time.Time           `json:"resolved_at,omitempty"`
	LastCheckAt     *time.Time           `json:"last_check_at,omitempty"`
	LastCheckStatus string               `json:"last_check_status"`
	Verification    *VerificationReceipt `json:"verification,omitempty"`
}
type Observation struct {
	EventKey                                  string
	Resource                                  Resource
	Kind, Condition, Severity, Title, Summary string
	IntentRevision, OperationID               int64
	ObservedAt                                time.Time
}

// VerificationToken fences a receipt against a newer occurrence or intent. A
// worker finishing, reading a message or acknowledging an issue is not a receipt.
type VerificationToken struct {
	IssueID        int64 `json:"issue_id"`
	Generation     int64 `json:"generation"`
	LatestEventID  int64 `json:"latest_event_id"`
	IntentRevision int64 `json:"intent_revision"`
}

// RecoveryCapability describes a typed action after a current-intent preflight.
// It is never inferred from visibility or from an arbitrary River job kind.
type RecoveryAction string

const (
	RecoveryRetryBackup   RecoveryAction = "retry_backup"
	RecoveryApplyDNS      RecoveryAction = "apply_dns"
	RecoveryRenewTLS      RecoveryAction = "renew_tls"
	RecoveryConfigureMail RecoveryAction = "configure_mail"
)

type RecoveryCapability struct {
	Action  RecoveryAction `json:"action"`
	Allowed bool           `json:"allowed"`
	Reason  string         `json:"reason,omitempty"`
}

func validText(s string, max int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= max && !strings.ContainsRune(s, '\x00')
}
func (o Observation) validate() error {
	if !o.Resource.Valid() || !validText(o.EventKey, 256) || !validText(o.Kind, 80) || !validText(o.Condition, 160) || !validText(o.Title, 200) || len(o.Summary) > 2000 || o.IntentRevision < 0 || o.OperationID < 0 || o.ObservedAt.IsZero() {
		return ErrInvalid
	}
	switch o.Severity {
	case "info", "warning", "critical":
		return nil
	default:
		return ErrInvalid
	}
}
