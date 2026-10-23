package quota

import (
	"bufio"
	"context"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/testutil/operationsdb"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNotificationEmailRecordsSMTPAcceptanceWithLoopbackCapture(t *testing.T) {
	db := operationsdb.New(t)
	ctx := context.Background()
	s := operations.NewStore(db)
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	if _, err := db.Exec(`UPDATE users SET email='operator@panel.example' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDeliveryPolicy(ctx, actor, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, actor, operations.Preferences{EmailMode: "immediate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveIssue(ctx, operations.Observation{EventKey: "smtp-fixture", Resource: operations.Resource{Kind: operations.ResourceServer}, Kind: "mail", Condition: "readiness", Severity: "critical", Title: "Mail readiness requires attention", Summary: "Open the current issue.", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	captured := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 fixture SMTP\r\n")
		var data strings.Builder
		reading := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if reading {
				if line == ".\r\n" {
					reading = false
					captured <- data.String()
					fmt.Fprint(conn, "250 accepted\r\n")
				} else {
					data.WriteString(line)
				}
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				fmt.Fprint(conn, "250 fixture\r\n")
			case strings.HasPrefix(upper, "MAIL"), strings.HasPrefix(upper, "RCPT"):
				fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(upper, "DATA"):
				reading = true
				fmt.Fprint(conn, "354 continue\r\n")
			case strings.HasPrefix(upper, "QUIT"):
				fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprint(conn, "250 OK\r\n")
			}
		}
	}()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	worker := NewDeliverNotificationsWorker(db, SMTPConfig{Host: "127.0.0.1", Port: port, From: "panel@sender.example", TLSMode: "none"})
	if err = worker.Work(ctx, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-captured:
		if !strings.Contains(message, "To: operator@panel.example") || !strings.Contains(message, "Mail readiness requires attention") {
			t.Fatal("capture mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no local SMTP acceptance")
	}
	var status string
	var at bool
	if err = db.QueryRow(`SELECT status,accepted_at IS NOT NULL FROM notification_email_batches`).Scan(&status, &at); err != nil || status != "accepted" || !at {
		t.Fatal(status, at, err)
	}
}
