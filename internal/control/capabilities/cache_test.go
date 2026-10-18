package capabilities

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type readerFunc func(context.Context) (types.RuntimeCapabilities, error)

func (f readerFunc) RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error) {
	return f(ctx)
}

func testValue(version string) types.RuntimeCapabilities {
	return types.RuntimeCapabilities{PHPVersions: []string{version}}
}

func useTestClock(c *Cache) func(time.Duration) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	c.now = func() time.Time { return time.Unix(0, nanos.Load()) }
	return func(d time.Duration) { nanos.Add(int64(d)) }
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for cache refresh")
		case <-time.After(time.Millisecond):
		}
	}
}

func requireValue(t *testing.T, c *Cache, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := c.RuntimeCapabilities(ctx)
	if err != nil || !reflect.DeepEqual(got, testValue(want)) {
		t.Fatalf("RuntimeCapabilities = %#v, %v; want version %s", got, err, want)
	}
}

func TestCacheTTL(t *testing.T) {
	var calls atomic.Int32
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			return testValue("8.4"), nil
		}
		return testValue("8.5"), nil
	}), WithTTL(time.Minute))
	advance := useTestClock(c)
	requireValue(t, c, "8.4")
	advance(time.Minute - time.Nanosecond)
	requireValue(t, c, "8.4")
	if calls.Load() != 1 {
		t.Fatalf("fresh cache made %d probes, want 1", calls.Load())
	}
	advance(time.Nanosecond)
	requireValue(t, c, "8.4")
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.hasValue && reflect.DeepEqual(c.value, testValue("8.5"))
	})
	requireValue(t, c, "8.5")
	if calls.Load() != 2 {
		t.Fatalf("expired cache made %d probes, want 2", calls.Load())
	}
}

func TestCacheConcurrentCallersShareProbe(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return testValue("8.5"), nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			got, err := c.RuntimeCapabilities(ctx)
			if err != nil || !reflect.DeepEqual(got, testValue("8.5")) {
				t.Errorf("RuntimeCapabilities = %#v, %v", got, err)
			}
		}()
	}
	close(gate)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("50 callers made %d probes, want 1", calls.Load())
	}
}

func TestCacheCallerCancellationDoesNotCancelProbe(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	c := New(readerFunc(func(ctx context.Context) (types.RuntimeCapabilities, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Second {
			t.Error("shared probe has no bounded deadline")
		}
		close(started)
		select {
		case <-release:
			return testValue("8.5"), nil
		case <-ctx.Done():
			return types.RuntimeCapabilities{}, ctx.Err()
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.RuntimeCapabilities(ctx); first <- err }()
	<-started
	second := make(chan error, 1)
	go func() {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer waitCancel()
		_, err := c.RuntimeCapabilities(waitCtx)
		second <- err
	}()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller error = %v", err)
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatalf("other waiter error = %v", err)
	}
	requireValue(t, c, "8.5")
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			return testValue("8.4"), nil
		}
		close(started)
		<-release
		return testValue("8.5"), nil
	}))
	advance := useTestClock(c)
	requireValue(t, c, "8.4")
	advance(5 * time.Minute)
	// Every stale read must finish while the refresh is still blocked.
	for i := 0; i < 50; i++ {
		requireValue(t, c, "8.4")
	}
	<-started
	if calls.Load() != 2 {
		t.Fatalf("stale reads made %d probes, want 2 including initial load", calls.Load())
	}
	close(release)
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.value.PHPVersions[0] == "8.5"
	})
	requireValue(t, c, "8.5")
}

func TestCacheRefreshErrorKeepsPreviousValue(t *testing.T) {
	probeErr := errors.New("agent unavailable")
	var calls atomic.Int32
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			return testValue("8.4"), nil
		}
		return testValue("bad partial value"), probeErr
	}))
	advance := useTestClock(c)
	requireValue(t, c, "8.4")
	advance(5 * time.Minute)
	requireValue(t, c, "8.4")
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return errors.Is(c.lastErr, probeErr)
	})
	for i := 0; i < 50; i++ {
		requireValue(t, c, "8.4")
	}
	if calls.Load() != 2 {
		t.Fatalf("failed refresh was retried during backoff: %d probes", calls.Load())
	}
}

func TestCacheInitialErrorBacksOff(t *testing.T) {
	probeErr := errors.New("agent unavailable")
	var calls atomic.Int32
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			return testValue("bad partial value"), probeErr
		}
		return testValue("8.5"), nil
	}))
	advance := useTestClock(c)
	for i := 0; i < 50; i++ {
		got, err := c.RuntimeCapabilities(context.Background())
		if !errors.Is(err, probeErr) || !reflect.DeepEqual(got, types.RuntimeCapabilities{}) {
			t.Fatalf("failed initial probe = %#v, %v", got, err)
		}
	}
	advance(15*time.Second - time.Nanosecond)
	if _, err := c.RuntimeCapabilities(context.Background()); !errors.Is(err, probeErr) || calls.Load() != 1 {
		t.Fatalf("backoff error = %v, probes = %d", err, calls.Load())
	}
	advance(time.Nanosecond)
	requireValue(t, c, "8.5")
	if calls.Load() != 2 {
		t.Fatalf("probes after backoff = %d, want 2", calls.Load())
	}
}

func TestCacheInvalidate(t *testing.T) {
	for _, initialError := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "backoff"}[initialError], func(t *testing.T) {
			var calls atomic.Int32
			c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
				if calls.Add(1) == 1 {
					if initialError {
						return types.RuntimeCapabilities{}, errors.New("unavailable")
					}
					return testValue("8.4"), nil
				}
				return testValue("8.5"), nil
			}))
			_, _ = c.RuntimeCapabilities(context.Background())
			c.Invalidate()
			requireValue(t, c, "8.5")
			if calls.Load() != 2 {
				t.Fatalf("probes after invalidation = %d, want 2", calls.Load())
			}
		})
	}
}

func TestCacheInvalidateDuringProbe(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return testValue("8.4"), nil
		}
		return testValue("8.5"), nil
	}))
	done := make(chan struct{})
	go func() { defer close(done); requireValue(t, c, "8.5") }()
	<-started
	c.Invalidate()
	requireValue(t, c, "8.5")
	close(release)
	<-done
	requireValue(t, c, "8.5")
	if calls.Load() != 2 {
		t.Fatalf("probes = %d, want 2", calls.Load())
	}
}

func TestCacheReturnsIndependentCopies(t *testing.T) {
	value := types.RuntimeCapabilities{
		PHPVersions: []string{"8.5"}, ApplicationHealth: []string{"http"},
		PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.5", Extensions: []string{"zip"}, MissingExtensions: []string{"curl"}, ValidationErrors: []string{"missing curl"}}},
	}
	want := clone(value)
	c := New(readerFunc(func(context.Context) (types.RuntimeCapabilities, error) { return value, nil }))
	got, err := c.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.PHPVersions[0] = "changed"
	got.ApplicationHealth[0] = "changed"
	got.PHPRuntimes[0].Version = "changed"
	got.PHPRuntimes[0].Extensions[0] = "changed"
	got.PHPRuntimes[0].MissingExtensions[0] = "changed"
	got.PHPRuntimes[0].ValidationErrors[0] = "changed"
	value.PHPVersions[0] = "reader changed"
	got, err = c.RuntimeCapabilities(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("cached value was mutated: %#v, %v", got, err)
	}
}

func TestCacheProbeTimeout(t *testing.T) {
	c := New(readerFunc(func(ctx context.Context) (types.RuntimeCapabilities, error) {
		<-ctx.Done()
		return types.RuntimeCapabilities{}, ctx.Err()
	}), WithProbeTimeout(10*time.Millisecond))
	if _, err := c.RuntimeCapabilities(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe timeout error = %v", err)
	}
}
