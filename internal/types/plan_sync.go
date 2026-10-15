package types

// PlanSynchronization separates the immutable subscription contract from
// asynchronous service convergence. Excluded subscriptions keep their snapshot.
type PlanSynchronization struct {
	PlanID        int64                  `json:"plan_id"`
	Revision      int                    `json:"revision"`
	State         string                 `json:"state"`
	Synced        int                    `json:"synced"`
	Pending       int                    `json:"pending"`
	Failed        int                    `json:"failed"`
	Excluded      int                    `json:"excluded"`
	Subscriptions []PlanSubscriptionSync `json:"subscriptions"`
}

type PlanSubscriptionSync struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Mode             string `json:"mode"`
	State            string `json:"state"`
	SnapshotRevision int    `json:"snapshot_revision"`
	Error            string `json:"error,omitempty"`
}
