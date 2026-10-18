package servertiming

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type recorderKey struct{}

type Recorder struct {
	mu      sync.Mutex
	started time.Time
	metrics map[string]time.Duration
}

func WithRecorder(ctx context.Context) context.Context {
	return context.WithValue(ctx, recorderKey{}, &Recorder{started: time.Now(), metrics: make(map[string]time.Duration)})
}

func Record(ctx context.Context, name string, duration time.Duration) {
	r, ok := ctx.Value(recorderKey{}).(*Recorder)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics[name] += duration
}

// Header returns an empty string for requests without a recorder.
func Header(ctx context.Context) string {
	r, ok := ctx.Value(recorderKey{}).(*Recorder)
	if !ok {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	metrics := make([]string, 0, len(names)+1)
	for _, name := range names {
		metrics = append(metrics, fmt.Sprintf("%s;dur=%.3f", name, float64(r.metrics[name])/float64(time.Millisecond)))
	}
	metrics = append(metrics, fmt.Sprintf("total;dur=%.3f", float64(time.Since(r.started))/float64(time.Millisecond)))
	return strings.Join(metrics, ", ")
}
