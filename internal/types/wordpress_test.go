package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWordPressUninstallContractsContainNoSecretOrPathFields(t *testing.T) {
	req := WordPressOperationReq{
		OperationID: 19,
		Action:      WordPressActionUninstall,
		Site: WordPressSiteSpec{
			InstanceID: 7, SubscriptionID: 3, SiteID: 11, DesiredRevision: 4,
			Username: "nps11", Domain: "example.test", HostingMode: PHPHostingModeClassic,
		},
		Removal: &WordPressRemovalSpec{
			DeleteDatabase: true,
			DatabaseName:   "wp_s11_deadbeef",
			DatabaseUser:   "wp_u11_deadbeef",
		},
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "secret", "archive_path", "document_root", "/home/"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("uninstall request exposed %q: %s", forbidden, encoded)
		}
	}

	result := WordPressOperationResult{Action: WordPressActionUninstall, Changed: true, Removal: &WordPressRemovalResult{
		FilesRemoved: true, DatabaseRemoved: true, BackupID: 31,
	}}
	encoded, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "secret", "archive_path", "quarantine", "/home/"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("uninstall result exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestWordPressRiverArgsContainOnlyIdentifiers(t *testing.T) {
	encoded, err := json.Marshal(WordPressOperationArgs{InstanceID: 7, OperationID: 9, DesiredRevision: 3})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"password", "admin_email", "db_name", "target_slug"} {
		if strings.Contains(text, secret) {
			t.Fatalf("River args expose %q: %s", secret, text)
		}
	}
}

func TestWordPressOperationRequestKeepsCredentialsInRPCPayload(t *testing.T) {
	req := WordPressOperationReq{Action: WordPressActionInstall, Credentials: &WordPressCredentials{
		DatabaseName: "np_wp", DatabaseUser: "np_wp_user", DatabasePassword: "database-secret",
		AdminUser: "siteadmin", AdminEmail: "admin@example.test", AdminPassword: "admin-secret",
	}}
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "database-secret") || !strings.Contains(string(encoded), "admin-secret") {
		t.Fatalf("protected RPC payload omitted credentials: %s", encoded)
	}
}
