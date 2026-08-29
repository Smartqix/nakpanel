package quota

import (
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestScheduledOccurrenceUsesTaskTimezone(t *testing.T) {
	now := time.Date(2026, time.July, 23, 14, 30, 42, 0, time.UTC)
	got, due := scheduledOccurrence("30 10 * * *", "America/New_York", now)
	if !due {
		t.Fatal("expected 10:30 America/New_York to be due")
	}
	if !got.Equal(time.Date(2026, time.July, 23, 14, 30, 0, 0, time.UTC)) {
		t.Fatalf("scheduled time = %s", got)
	}
	if _, due = scheduledOccurrence("31 10 * * *", "America/New_York", now); due {
		t.Fatal("future schedule reported due")
	}
}

func TestScheduledTasksAllowedFailsClosedOnPolicyRevocation(t *testing.T) {
	var policy types.HostingPolicy
	if scheduledTasksAllowed(policy) {
		t.Fatal("scheduled tasks remained runnable without an entitlement")
	}
	policy.Permissions.ScheduledTasks = true
	if !scheduledTasksAllowed(policy) {
		t.Fatal("scheduled tasks were blocked despite an explicit entitlement")
	}
}

func TestScheduledOccurrenceRejectsInvalidInput(t *testing.T) {
	now := time.Now()
	if _, due := scheduledOccurrence("not cron", "UTC", now); due {
		t.Fatal("invalid cron reported due")
	}
	if _, due := scheduledOccurrence("* * * * *", "Mars/Olympus", now); due {
		t.Fatal("invalid timezone reported due")
	}
}
