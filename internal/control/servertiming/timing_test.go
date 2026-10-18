package servertiming

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecorder(t *testing.T) {
	ctx := WithRecorder(context.Background())
	Record(ctx, "load", 1500*time.Microsecond)
	Record(ctx, "caps", time.Millisecond)
	Record(ctx, "load", 500*time.Microsecond)
	Record(ctx, "render", 0)
	if got := Header(ctx); !strings.HasPrefix(got, "caps;dur=1.000, load;dur=2.000, render;dur=0.000, total;dur=") {
		t.Fatalf("Header = %q", got)
	}
}

func TestNoRecorder(t *testing.T) {
	ctx := context.Background()
	Record(ctx, "load", time.Second)
	if got := Header(ctx); got != "" {
		t.Fatalf("Header without recorder = %q", got)
	}
}

func TestRecorderConcurrentAndRequestScoped(t *testing.T) {
	ctx := WithRecorder(context.Background())
	other := WithRecorder(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Record(ctx, "caps", time.Millisecond)
			_ = Header(ctx)
		}()
	}
	wg.Wait()
	if got := Header(ctx); !strings.Contains(got, "caps;dur=50.000") {
		t.Fatalf("Header = %q", got)
	}
	if got := Header(other); strings.Contains(got, "caps") {
		t.Fatalf("other request inherited metrics: %q", got)
	}
}
