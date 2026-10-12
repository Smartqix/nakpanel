package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPHPRuntimeLimitShowsFiniteProviderCeiling(t *testing.T) {
	var b bytes.Buffer
	if err := phpRuntimeLimit("Maximum requests", "site_fpm_requests", 500, 500).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`min="1"`, `max="500"`, `required`, `value="500"`, `Provider maximum:`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s: %s", want, b.String())
		}
	}
	b.Reset()
	if err := phpRuntimeLimit("Maximum requests", "site_fpm_requests", 500, -1).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `max=`) {
		t.Fatal("unlimited provider must not get a finite browser maximum")
	}
}
