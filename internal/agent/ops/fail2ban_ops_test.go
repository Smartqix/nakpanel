package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeFail2BanRunner struct {
	commands [][]string
	outputs  map[string][]byte
	failOn   string
}

func (f *fakeFail2BanRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := append([]string{name}, args...)
	f.commands = append(f.commands, command)
	key := strings.Join(command, " ")
	if f.failOn != "" && strings.Contains(key, f.failOn) {
		return []byte("simulated failure"), errors.New("exit status 255")
	}
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	return nil, nil
}

func TestApplyFail2BanPolicyWritesAndReloads(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nakpanel.local")
	runner := &fakeFail2BanRunner{}
	controller := NewFail2BanController(Fail2BanControllerOptions{ConfigPath: configPath, Runner: runner})

	result, err := controller.ApplyFail2BanPolicy(context.Background(), types.ApplyFail2BanPolicyReq{
		Policy: types.Fail2BanPolicy{
			Jails: []types.Fail2BanJail{
				{ID: "sshd", Enabled: true, BanTime: 3600, FindTime: 600, MaxRetry: 5},
				{ID: "nakpanel-login", Enabled: true, MaxRetry: 5},
			},
		},
		SSHPorts: []int{22},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !result.Reloaded || result.ConfigPath != configPath {
		t.Fatalf("unexpected result %+v", result)
	}
	rendered, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[sshd]", "[nakpanel-login]", "banaction = nftables-multiport"} {
		if !strings.Contains(string(rendered), want) {
			t.Fatalf("config missing %q:\n%s", want, rendered)
		}
	}
}

func TestApplyFail2BanPolicyRestoresPreviousOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nakpanel.local")
	previous := "# previous good config\n"
	if err := os.WriteFile(configPath, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeFail2BanRunner{failOn: "reload"}
	controller := NewFail2BanController(Fail2BanControllerOptions{ConfigPath: configPath, Runner: runner})
	_, err := controller.ApplyFail2BanPolicy(context.Background(), types.ApplyFail2BanPolicyReq{
		Policy: types.Fail2BanPolicy{Jails: []types.Fail2BanJail{{ID: "sshd", Enabled: true}}},
	})
	if err == nil {
		t.Fatal("expected reload failure")
	}
	restored, readErr := os.ReadFile(configPath)
	if readErr != nil || string(restored) != previous {
		t.Fatalf("previous config was not restored: %q %v", restored, readErr)
	}
}

func TestListSecurityBansParsesClientOutput(t *testing.T) {
	runner := &fakeFail2BanRunner{outputs: map[string][]byte{
		"fail2ban-client status": []byte("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nakpanel-login\n"),
		"fail2ban-client status sshd": []byte(
			"Status for the jail: sshd\n|- Filter\n`- Actions\n   |- Currently banned:\t1\n   `- Banned IP list:\t203.0.113.9\n"),
		"fail2ban-client status nakpanel-login": []byte(
			"Status for the jail: nakpanel-login\n`- Actions\n   `- Banned IP list:\t\n"),
	}}
	controller := NewFail2BanController(Fail2BanControllerOptions{ConfigPath: filepath.Join(t.TempDir(), "x"), Runner: runner})
	result, err := controller.ListSecurityBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Running || len(result.Jails) != 2 {
		t.Fatalf("unexpected result %+v", result)
	}
	if result.Jails[0].Jail != "sshd" || len(result.Jails[0].Banned) != 1 || result.Jails[0].Banned[0] != "203.0.113.9" {
		t.Fatalf("sshd bans not parsed: %+v", result.Jails[0])
	}
	if len(result.Jails[1].Banned) != 0 {
		t.Fatalf("expected empty ban list, got %+v", result.Jails[1])
	}
}

func TestUnbanSecurityAddressValidatesInput(t *testing.T) {
	runner := &fakeFail2BanRunner{}
	controller := NewFail2BanController(Fail2BanControllerOptions{ConfigPath: filepath.Join(t.TempDir(), "x"), Runner: runner})
	if _, err := controller.UnbanSecurityAddress(context.Background(), types.UnbanSecurityAddressReq{JailID: "sshd; rm -rf /", Address: "1.2.3.4"}); err == nil {
		t.Fatal("expected invalid jail rejection")
	}
	if _, err := controller.UnbanSecurityAddress(context.Background(), types.UnbanSecurityAddressReq{JailID: "sshd", Address: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid address rejection")
	}
	result, err := controller.UnbanSecurityAddress(context.Background(), types.UnbanSecurityAddressReq{JailID: "sshd", Address: "203.0.113.9"})
	if err != nil || !result.Unbanned {
		t.Fatalf("unban failed: %+v %v", result, err)
	}
}
