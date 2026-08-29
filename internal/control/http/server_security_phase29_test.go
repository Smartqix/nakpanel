package panelhttp

import (
	"regexp"
	"testing"
)

func TestSecurityOperationIDMatchesServerOperationIdentity(t *testing.T) {
	operationID, err := newSecurityOperationID()
	if err != nil {
		t.Fatalf("generate security operation ID: %v", err)
	}
	if !regexp.MustCompile(`^op_[A-Za-z0-9_-]{20,64}$`).MatchString(operationID) {
		t.Fatalf("security operation ID %q does not satisfy the server operation identity contract", operationID)
	}
}
