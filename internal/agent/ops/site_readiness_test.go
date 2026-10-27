package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSiteReadinessRequiresItsOwnEnabledVhostAndIsolatedSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "np-readiness-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), PHPFPMDedicatedDir: filepath.Join(root, "php"), PHPFPMDedicatedRunDir: filepath.Join(root, "run")}
	req := types.InspectSiteReadinessReq{SiteID: 51, SubscriptionID: 42, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4"}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 51, SubscriptionID: 42, Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion, SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(plan.NginxConfig), filepath.Dir(plan.NginxEnabled), filepath.Dir(plan.PHPFPMConfig), filepath.Dir(plan.PHPFPMSocket)} {
		if err = os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	nginx := RenderNginxVHost(plan)
	pool := RenderPHPFPMPool(plan)
	if err = os.WriteFile(plan.NginxConfig, []byte(nginx), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(plan.PHPFPMConfig, []byte(pool), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", plan.PHPFPMSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths})
	result, err := p.InspectSiteReadiness(context.Background(), req)
	if err != nil || !result.Ready {
		t.Fatalf("current runtime: %#v %v", result, err)
	}
	corrupt := strings.Replace(pool, "user = npdemo", "user = another", 1)
	if err = os.WriteFile(plan.PHPFPMConfig, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	result, err = p.InspectSiteReadiness(context.Background(), req)
	if err != nil || result.Ready {
		t.Fatalf("another tenant's FPM pool accepted: %#v %v", result, err)
	}
	if err = os.WriteFile(plan.PHPFPMConfig, []byte(pool), 0600); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	result, err = p.InspectSiteReadiness(context.Background(), req)
	if err != nil || result.Ready {
		t.Fatalf("stopped FPM socket accepted: %#v %v", result, err)
	}
	after, err := os.ReadFile(plan.NginxConfig)
	if err != nil || string(after) != nginx {
		t.Fatal("readiness probe changed hosting configuration")
	}
}

func TestDedicatedFPMSocketWaitAllowsBoundedServiceInitialization(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "np-fpm-ready-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	socket := filepath.Join(root, "site.sock")
	type outcome struct {
		listener net.Listener
		err      error
	}
	ready := make(chan outcome, 1)
	timer := time.AfterFunc(3500*time.Millisecond, func() {
		listener, err := net.Listen("unix", socket)
		ready <- outcome{listener, err}
	})
	defer func() {
		if !timer.Stop() {
			result := <-ready
			if result.listener != nil {
				result.listener.Close()
			}
		}
	}()
	if err := waitForUnixSocket(context.Background(), socket, dedicatedFPMSocketReadyTimeout); err != nil {
		t.Fatalf("service was rejected before its socket could initialize: %v", err)
	}
}

func TestDedicatedFPMSocketWaitHonorsCancellationAndRejectsRegularFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-socket")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForUnixSocket(ctx, file, dedicatedFPMSocketReadyTimeout); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait ignored cancellation or accepted a regular file: %v", err)
	}
	if err := waitForUnixSocket(context.Background(), filepath.Join(root, "missing"), 20*time.Millisecond); err == nil {
		t.Fatal("missing socket was accepted")
	}
}
