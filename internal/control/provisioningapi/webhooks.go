package provisioningapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/riverqueue/river"
)

const WebhookQueue = "webhooks"

type WebhookConfig struct{ URL, Secret string }

func (c WebhookConfig) Validate() error {
	if strings.TrimSpace(c.URL) == "" && c.Secret == "" {
		return nil
	}
	if strings.TrimSpace(c.URL) == "" || c.Secret == "" {
		return errors.New("billing webhook URL and secret must be configured together")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("billing webhook URL is invalid")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return errors.New("billing webhook URL must use HTTPS")
	}
	return nil
}

type SweepWebhookArgs struct{}

func (SweepWebhookArgs) Kind() string { return "sweep_billing_webhooks" }
func (SweepWebhookArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: WebhookQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByPeriod: 30 * time.Second}}
}

type SweepWebhookWorker struct {
	river.WorkerDefaults[SweepWebhookArgs]
	db      *sql.DB
	river   *river.Client[*sql.Tx]
	enabled bool
}

func NewSweepWebhookWorker(db *sql.DB, enabled bool) *SweepWebhookWorker {
	return &SweepWebhookWorker{db: db, enabled: enabled}
}
func (w *SweepWebhookWorker) SetRiverClient(client *river.Client[*sql.Tx]) { w.river = client }
func (w *SweepWebhookWorker) Work(ctx context.Context, _ *river.Job[SweepWebhookArgs]) error {
	if !w.enabled || w.db == nil || w.river == nil {
		return nil
	}
	if _, err := w.db.ExecContext(ctx, `WITH exceeded AS (
SELECT b.id,b.public_id,u.period_start,u.disk_bytes,u.traffic_bytes,e.disk_mb,e.bandwidth_mb
FROM billing_accounts b JOIN subscription_usage_current u ON u.subscription_id=b.subscription_id
JOIN subscription_entitlements e ON e.subscription_id=b.subscription_id
WHERE u.is_complete AND b.provisioning_state NOT IN ('terminating','terminated')
AND ((e.disk_mb>=0 AND u.disk_bytes>e.disk_mb::bigint*1048576) OR (e.bandwidth_mb>=0 AND u.traffic_bytes>e.bandwidth_mb::bigint*1048576))
), marked AS (
UPDATE billing_accounts b SET over_limit=true,updated_at=now() FROM exceeded x WHERE b.id=x.id RETURNING b.id
)
INSERT INTO billing_webhook_outbox(delivery_id,billing_account_id,event_type,dedupe_key,payload)
SELECT 'whd_'||md5(random()::text||clock_timestamp()::text||x.id::text),x.id,'account.usage_exceeded',
'account.usage_exceeded:'||x.id||':'||x.period_start||':'||x.disk_bytes||':'||x.traffic_bytes,
jsonb_build_object('event','account.usage_exceeded','account_id',x.public_id,'period_start',x.period_start,'usage',jsonb_build_object('disk_bytes',x.disk_bytes,'bandwidth_bytes',x.traffic_bytes),'limits',jsonb_build_object('disk_bytes',CASE WHEN x.disk_mb<0 THEN -1 ELSE x.disk_mb::bigint*1048576 END,'bandwidth_bytes',CASE WHEN x.bandwidth_mb<0 THEN -1 ELSE x.bandwidth_mb::bigint*1048576 END),'occurred_at',now())
FROM exceeded x ON CONFLICT(dedupe_key) DO NOTHING`); err != nil {
		return err
	}
	rows, err := w.db.QueryContext(ctx, `SELECT id FROM billing_webhook_outbox WHERE status IN ('pending','failed') ORDER BY created_at,id LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return err
		}
		if _, err = w.river.Insert(ctx, DeliverWebhookArgs{OutboxID: id}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

type DeliverWebhookArgs struct {
	OutboxID int64 `json:"outbox_id" river:"unique"`
}

func (DeliverWebhookArgs) Kind() string { return "deliver_billing_webhook" }
func (DeliverWebhookArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: WebhookQueue, MaxAttempts: 12, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates()}}
}

type DeliverWebhookWorker struct {
	river.WorkerDefaults[DeliverWebhookArgs]
	db     *sql.DB
	config WebhookConfig
	client *http.Client
}

func NewDeliverWebhookWorker(db *sql.DB, c WebhookConfig) *DeliverWebhookWorker {
	return &DeliverWebhookWorker{db: db, config: c, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (w *DeliverWebhookWorker) Work(ctx context.Context, job *river.Job[DeliverWebhookArgs]) error {
	if err := w.config.Validate(); err != nil {
		return err
	}
	if w.config.URL == "" {
		return nil
	}
	var delivery, event, status string
	var body []byte
	err := w.db.QueryRowContext(ctx, `UPDATE billing_webhook_outbox SET status='delivering',attempts=attempts+1,updated_at=now() WHERE id=$1 AND status<>'sent' RETURNING delivery_id,event_type,payload::text,status`, job.Args.OutboxID).Scan(&delivery, &event, &body, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignWebhook(w.config.Secret, timestamp, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nakpanel-Signature", "sha256="+signature)
	req.Header.Set("X-Nakpanel-Timestamp", timestamp)
	req.Header.Set("X-Nakpanel-Event", event)
	req.Header.Set("X-Nakpanel-Delivery", delivery)
	res, err := w.client.Do(req)
	if err != nil {
		w.fail(ctx, job.Args.OutboxID, 0, err.Error())
		return err
	}
	defer res.Body.Close()
	summary, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		message := fmt.Sprintf("webhook returned %d: %s", res.StatusCode, strings.TrimSpace(string(summary)))
		w.fail(ctx, job.Args.OutboxID, res.StatusCode, message)
		return errors.New(message)
	}
	_, err = w.db.ExecContext(ctx, `UPDATE billing_webhook_outbox SET status='sent',response_status=$2,last_error='',sent_at=now(),updated_at=now() WHERE id=$1`, job.Args.OutboxID, res.StatusCode)
	return err
}

func SignWebhook(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
func (w *DeliverWebhookWorker) fail(ctx context.Context, id int64, status int, message string) {
	if len(message) > 2048 {
		message = message[:2048]
	}
	_, _ = w.db.ExecContext(ctx, `UPDATE billing_webhook_outbox SET status='failed',response_status=NULLIF($2,0),last_error=$3,updated_at=now() WHERE id=$1`, id, status, message)
}
