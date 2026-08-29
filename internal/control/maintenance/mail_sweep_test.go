package maintenance

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailSweepAgent struct {
	queue types.CollectMailQueueResult
}

func (a mailSweepAgent) CollectMailQueue(context.Context) (types.Response, error) {
	data, err := json.Marshal(a.queue)
	return types.Response{OK: err == nil, Data: data}, err
}

func TestMailQueueSweepDoesNotResolveAlertFromIncompleteSnapshot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, nil, nil)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT md.domain,md.subscription_id,sub.customer_id")).
		WillReturnRows(sqlmock.NewRows([]string{"domain", "subscription_id", "customer_id"}).
			AddRow("example.test", int64(3), int64(2)))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT mail_hostname,smarthost_host,smarthost_port,smarthost_username,smarthost_password,outbound_rate_limit,queue_alert_threshold FROM mail_settings WHERE id")).
		WillReturnRows(sqlmock.NewRows([]string{
			"mail_hostname", "smarthost_host", "smarthost_port", "smarthost_username",
			"smarthost_password", "outbound_rate_limit", "queue_alert_threshold",
		}).AddRow("mail.example.test", "", 587, "", "", "200/1h", 50))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM users WHERE email='scheduler@nakpanel.internal' AND login_disabled=true")).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(99)))

	err = service.sweepMailQueue(context.Background(), mailSweepAgent{queue: types.CollectMailQueueResult{
		TotalQueued: 1001, SenderDomains: map[string]int{"example.test": 1}, Truncated: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("an incomplete snapshot attempted to resolve the alert: %v", err)
	}
}
