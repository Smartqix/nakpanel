package ops

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type orderedRuntimeProbe struct {
	*fakeRuntimeCapabilityProbe
	started   chan string
	completed chan string
	release   map[string]chan struct{}
}

func (p *orderedRuntimeProbe) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "-r" {
		version := strings.TrimPrefix(filepath.Base(name), "php")
		p.started <- version
		select {
		case <-p.release[version]:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	output, err := p.fakeRuntimeCapabilityProbe.Run(ctx, name, args...)
	if len(args) > 0 && args[0] == "-v" && strings.HasPrefix(filepath.Base(name), "php-fpm") {
		p.completed <- strings.TrimPrefix(filepath.Base(name), "php-fpm")
	}
	return output, err
}

func TestProbePHPRuntimesConcurrentPreservesOrder(t *testing.T) {
	probe := &orderedRuntimeProbe{
		fakeRuntimeCapabilityProbe: completeRuntimeProbe("8.5", "8.4", "8.3"),
		started:                    make(chan string, 3), completed: make(chan string, 3),
		release: map[string]chan struct{}{"8.5": make(chan struct{}), "8.4": make(chan struct{}), "8.3": make(chan struct{})},
	}
	// Reject FPM at its version check so this unit test needs no host sockets.
	var wantRuntimes []types.PHPRuntimeCapability
	for _, supported := range supportedPHPRuntimes {
		fpm := probe.paths["php-fpm"+supported.version]
		probe.outputs[runtimeCommandKey(fpm, "-v")] = []byte("PHP 7.4.33 (fpm-fcgi)\n")
		runtime, _ := probePHPRuntime(context.Background(), probe.fakeRuntimeCapabilityProbe, supported.version, supported.status)
		wantRuntimes = append(wantRuntimes, runtime)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var runtimes []types.PHPRuntimeCapability
	var ready []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtimes, ready = probePHPRuntimes(ctx, probe)
	}()
	for range supportedPHPRuntimes {
		select {
		case <-probe.started:
		case <-ctx.Done():
			t.Fatal("PHP version probes did not start concurrently")
		}
	}
	// Finish in the opposite order to the supported version list.
	for _, version := range []string{"8.3", "8.4", "8.5"} {
		close(probe.release[version])
		select {
		case got := <-probe.completed:
			if got != version {
				t.Fatalf("completed version = %s, want %s", got, version)
			}
		case <-ctx.Done():
			t.Fatal("PHP version probe did not complete")
		}
	}
	<-done
	want := []string{"8.5", "8.4", "8.3"}
	var versions []string
	for _, runtime := range runtimes {
		versions = append(versions, runtime.Version)
	}
	if !reflect.DeepEqual(versions, want) || len(ready) != 0 || !reflect.DeepEqual(runtimes, wantRuntimes) {
		t.Fatalf("runtimes = %#v, ready = %v; want ordered runtimes %#v and no ready versions", runtimes, ready, wantRuntimes)
	}
}
