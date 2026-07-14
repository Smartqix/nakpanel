package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubscriptionTeardownDeletesOnlyValidatedAccountHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "npaccount")
	if err := os.MkdirAll(filepath.Join(home, "domains", "example.test"), 0o750); err != nil {
		t.Fatal(err)
	}
	runner := &teardownRunner{}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{HomeRoot: root, Paths: SitePathConfig{HomeRoot: root, NginxAvailableDir: t.TempDir(), NginxEnabledDir: t.TempDir(), NginxConfDir: t.TempDir(), PHPFPMPoolDir: t.TempDir()}, Runner: runner})
	result, err := p.TeardownSubscription(context.Background(), types.TeardownSubscriptionReq{SubscriptionID: 4, Username: "npaccount", HomePath: home, Domains: []string{"example.test"}, DatabaseNames: []string{"np_4_app"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home still exists: %v", err)
	}
	if len(result.Removed) == 0 {
		t.Fatal("missing per-resource progress")
	}
	if !runner.saw("userdel", "--", "npaccount") {
		t.Fatalf("userdel not bounded to account: %#v", runner.calls)
	}
}

func TestSubscriptionTeardownRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "npaccount")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{HomeRoot: root, Runner: &teardownRunner{}})
	requests := []types.TeardownSubscriptionReq{
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "..", "outside")},
		{SubscriptionID: 1, Username: "npaccount;rm", HomePath: filepath.Join(root, "npaccount;rm")},
		{SubscriptionID: 1, Username: "npaccount", HomePath: link},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), Domains: []string{"../bad"}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), DatabaseNames: []string{"db;DROP"}},
	}
	for i, req := range requests {
		if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
			t.Fatalf("unsafe request %d was accepted", i)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside directory changed: %v", err)
	}
}

type teardownRunner struct{ calls [][]string }

func (r *teardownRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil, nil
}
func (r *teardownRunner) saw(want ...string) bool {
	for _, call := range r.calls {
		if len(call) != len(want) {
			continue
		}
		same := true
		for i := range call {
			same = same && call[i] == want[i]
		}
		if same {
			return true
		}
	}
	return false
}
