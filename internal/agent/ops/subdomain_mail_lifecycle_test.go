package ops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubdomainMailDisableKeepsStoreAndSigningKeys(t *testing.T) {
	p := testMailProvisioner(t, &recordingPhase6Reloader{})
	domains := []types.MailDomainConfig{{SiteID: 1, SubscriptionID: 1, MailDomainID: 1, Domain: "parent.test", DKIM: true}, {SiteID: 2, SubscriptionID: 1, MailDomainID: 2, Domain: "shop.parent.test", DKIM: true}, {SiteID: 3, SubscriptionID: 1, MailDomainID: 3, Domain: "news.parent.test", DKIM: true}}
	files := map[string][]byte{}
	for _, domain := range domains {
		path := filepath.Join(p.dataDir, "blobs", domain.Domain, "fixture.eml")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		data := []byte("To: hello@" + domain.Domain + "\r\nSubject: preserved canary\r\n\r\nmessage bytes\r\n")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		files[path] = data
	}
	for i, enabled := range [][]types.MailDomainConfig{domains, {domains[0], domains[2]}, nil, domains} {
		if _, err := p.ConfigureMail(context.Background(), types.ConfigureMailReq{Hostname: "mail.node.test", Domains: enabled}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			for _, domain := range domains {
				path := filepath.Join(p.dkimDir, domain.Domain, DKIMSelector+".key")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				files[path] = data
			}
		}
		for path, want := range files {
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(want) {
				t.Fatalf("disable/re-enable changed canary %s: %v", filepath.Base(path), err)
			}
		}
	}
}
