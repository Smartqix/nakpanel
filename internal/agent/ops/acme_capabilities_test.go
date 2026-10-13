package ops

import (
	"context"
	"testing"
)

func TestRuntimeCapabilitiesReportsConfiguredACME(t *testing.T) {
	for _, available := range []bool{false, true} {
		collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(completeRuntimeProbe()), WithACMEAvailability(available))
		got, err := collector.RuntimeCapabilities(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.ACMEAvailable != available {
			t.Fatalf("ACME available=%v want=%v", got.ACMEAvailable, available)
		}
	}
}
