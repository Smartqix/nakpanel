package wordpress

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOperationJobsCarryIdentifiersOnly(t *testing.T) {
	payload, err := json.Marshal(OperationArgs{InstanceID: 1, OperationID: 2, DesiredRevision: 3})
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.ToLower(string(payload))
	for _, forbidden := range []string{"password", "secret", "email", "database", "domain", "username", "command", "path"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("job payload contains %q: %s", forbidden, payload)
		}
	}
}

func TestCleanupRemovalJobsCarryIdentifiersOnly(t *testing.T) {
	payload, err := json.Marshal(CleanupRemovalArgs{InstanceID: 1, OperationID: 2, DesiredRevision: 3})
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.ToLower(string(payload))
	for _, forbidden := range []string{"password", "secret", "database", "domain", "username", "path", "archive"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("cleanup payload contains %q: %s", forbidden, payload)
		}
	}
}
