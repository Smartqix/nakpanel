package web

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/operations"
)

func TestNotificationTimeLabels(t *testing.T) {
	now := time.Date(2026, 10, 28, 14, 40, 0, 0, time.UTC)
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, "Unknown time"}, {now.Add(time.Hour), "Just now"}, {now.Add(-30 * time.Second), "Just now"},
		{now.Add(-time.Minute), "1 min ago"}, {now.Add(-59 * time.Minute), "59 min ago"}, {now.Add(-time.Hour), "1 hr ago"},
		{now.Add(-23 * time.Hour), "23 hr ago"}, {now.Add(-24 * time.Hour), "27 Oct 2026"},
	} {
		if got := notificationTimeLabel(tc.at, now); got != tc.want {
			t.Fatalf("%s: %q want %q", tc.at, got, tc.want)
		}
	}
}

func TestNotificationPreviewAndViews(t *testing.T) {
	now := time.Date(2026, 10, 28, 14, 40, 0, 0, time.UTC)
	for _, count := range []int{0, 1, 5, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			p := operations.Page{CheckedAt: now, Counts: operations.Counts{Unread: 1}}
			for i := 0; i < count; i++ {
				p.Notifications = append(p.Notifications, operations.Notification{ID: int64(i + 1), Kind: "unknown", Title: "<script>bad</script>", Summary: strings.Repeat("safe ", 400), Target: strings.Repeat("a", 253), CreatedAt: now.Add(-5 * time.Minute)})
			}
			var b bytes.Buffer
			if err := notificationPreview(WorkspaceView{SelectedSubscription: 42, SupportCustomerID: 10}, p).Render(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			html := b.String()
			want := count
			if want > 5 {
				want = 5
			}
			if got := strings.Count(html, "data-np-notification-id="); got != want {
				t.Fatalf("rows %d want %d", got, want)
			}
			for _, v := range []string{"np-notification-preview", "View all notifications", "data-np-notification-status", "data-np-notification-error", "/support/customers/10/activity?subscription_id=42&amp;tab=inbox"} {
				if !strings.Contains(html, v) {
					t.Fatal("missing", v)
				}
			}
			if count > 0 {
				for _, v := range []string{"&lt;script&gt;bad&lt;/script&gt;", strings.Repeat("safe ", 400), strings.Repeat("a", 253), `datetime="2026-10-28T14:35:00Z"`, "5 min ago", "Actions for", `hidden`} {
					if !strings.Contains(html, v) {
						t.Fatal("missing safe row content", v)
					}
				}
			}
			if strings.Contains(html, "@icon(") {
				t.Fatal("templ call leaked as visible text")
			}
			if strings.Contains(html, "<script>bad") || strings.Contains(html, ">Mark read</button>") || strings.Contains(html, `class="np-op-row"`) {
				t.Fatal("unsafe or wide legacy row", html)
			}
		})
	}
}

func TestNotificationContextAndInbox(t *testing.T) {
	if got := notificationContext(operations.Notification{}); got != "Workspace" {
		t.Fatal(got)
	}
	now := time.Now().UTC()
	p := operations.Page{CheckedAt: now, Notifications: []operations.Notification{{ID: 3, Title: "Sign-in", Summary: "Account detail", Target: "Your account", CreatedAt: now}}}
	var b bytes.Buffer
	if err := notificationInbox(WorkspaceView{OperationsTab: "inbox"}, p).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"Search notifications", "Mark all read", "data-np-notification-list", "data-np-notification-filter", "UTC", "Account detail"} {
		if !strings.Contains(b.String(), v) {
			t.Fatal("missing", v)
		}
	}
}
