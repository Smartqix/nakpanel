package types

type GitWorkspaceOperationInput struct {
	Action           string `json:"action"`
	Revision         string `json:"revision"`
	ExpectedRevision int64  `json:"expected_revision"`
	ConfirmOverwrite bool   `json:"confirm_overwrite"`
	IdempotencyKey   string `json:"idempotency_key"`
}
