package ops

import (
	"context"
	"testing"
)

func TestRuntimeCapabilitiesGoAccess(t *testing.T) {
	for _, output := range []string{"GoAccess - 1.9.4", "GoAccess 1.9.4", "unrecognized"} {
		probe := completeRuntimeProbe()
		probe.addTool("goaccess", "/usr/bin/goaccess", []byte(output))
		collector := &UsageCollector{runtimeProbe: probe}
		got, err := collector.RuntimeCapabilities(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want := output != "unrecognized"
		if got.GoAccessAvailable != want {
			t.Fatalf("output %q: %#v", output, got)
		}
		if want && got.GoAccessVersion != "1.9.4" {
			t.Fatalf("version = %q", got.GoAccessVersion)
		}
	}
}
