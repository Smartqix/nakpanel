package webstatistics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"time"
)

var ErrNotFound = errors.New("statistics not found")
var ErrDisabled = errors.New("web statistics disabled")
var ErrCooldown = errors.New("statistics refresh is already pending or rate limited")

type Agent interface {
	GenerateWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error)
	ReadWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error)
	WebStatisticsStatus(context.Context) (types.WebStatisticsStatus, error)
}
type Inserter interface {
	InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
}
type Service struct {
	db    *sql.DB
	agent Agent
	queue Inserter
}

func New(db *sql.DB, agent Agent, queue Inserter) *Service {
	return &Service{db: db, agent: agent, queue: queue}
}
func (s *Service) SetRiverClient(queue Inserter) { s.queue = queue }
func (s *Service) Configure(ctx context.Context, actor auth.SessionUser, siteID int64, engine string) error {
	v, err := s.Workspace(ctx, actor, siteID)
	if err != nil {
		return err
	}
	if !v.Active || !v.CanConfigure {
		return ErrDisabled
	}
	store := controlquota.NewSQLStore(s.db)
	if engine == "inherit" {
		return store.ResetSitePolicy(ctx, siteID, actor.ID, "logs")
	}
	if engine != "disabled" && engine != "goaccess" {
		return errors.New("invalid statistics engine")
	}
	patch, _ := json.Marshal(map[string]any{"logs": map[string]any{"statistics_engine": engine, "statistics_enabled": engine == "goaccess"}})
	return store.SetSitePolicy(ctx, siteID, actor.ID, patch)
}

type Settings struct {
	Enabled                     bool
	RetentionDays, ScheduleHour int
	AnonymizeIP                 bool
	Revision                    int64
	Engine                      types.WebStatisticsStatus
}
type Workspace struct {
	Enabled, CanConfigure, Active, ReportAvailable, Overridden bool
	Engine, Status, LastError                                  string
	RequestedAt, GeneratedAt                                   time.Time
	Summary                                                    types.WebStatisticsSummary
	Settings                                                   Settings
}

func (s *Service) settings(ctx context.Context, tx *sql.Tx) (Settings, error) {
	var v Settings
	err := tx.QueryRowContext(ctx, `SELECT enabled,retention_days,schedule_hour,anonymize_ip,revision FROM web_statistics_settings WHERE id=1`).Scan(&v.Enabled, &v.RetentionDays, &v.ScheduleHour, &v.AnonymizeIP, &v.Revision)
	return v, err
}
func (s *Service) Settings(ctx context.Context, actor auth.SessionUser) (Settings, error) {
	if actor.Role != auth.RoleAdmin {
		return Settings{}, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback()
	v, err := s.settings(ctx, tx)
	if err == nil {
		v.Engine, err = s.agent.WebStatisticsStatus(ctx)
	}
	return v, err
}
func (s *Service) SaveSettings(ctx context.Context, actor auth.SessionUser, v Settings) error {
	if actor.Role != auth.RoleAdmin {
		return ErrNotFound
	}
	if v.RetentionDays < 1 || v.RetentionDays > 90 || v.ScheduleHour < 0 || v.ScheduleHour > 23 {
		return errors.New("invalid statistics settings")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE web_statistics_settings SET enabled=$1,retention_days=$2,schedule_hour=$3,anonymize_ip=$4,revision=revision+CASE WHEN retention_days<>$2 OR anonymize_ip<>$4 THEN 1 ELSE 0 END WHERE id=1`, v.Enabled, v.RetentionDays, v.ScheduleHour, v.AnonymizeIP)
	return err
}

func (s *Service) identity(ctx context.Context, tx *sql.Tx, actor *auth.SessionUser, siteID int64) (types.WebStatisticsRequest, bool, error) {
	req := types.WebStatisticsRequest{SiteID: siteID}
	var active bool
	query := `SELECT site.domain,site.username,site.desired_status='active' AND subscription.status='active' AND customer.status='active'
AND (customer.reseller_id IS NULL OR EXISTS(SELECT 1 FROM reseller_accounts ra JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active' WHERE ra.id=customer.reseller_id AND ra.status='active'))
AND NOT EXISTS(SELECT 1 FROM billing_accounts billing WHERE billing.subscription_id=subscription.id AND billing.provisioning_state IN ('terminating','terminated'))
FROM sites site JOIN subscriptions subscription ON subscription.id=site.subscription_id JOIN customers customer ON customer.id=subscription.customer_id
WHERE site.id=$1`
	args := []any{siteID}
	if actor != nil {
		query += ` AND ($2='admin' OR ($2='client' AND customer.login_user_id=$3) OR ($2='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts ra WHERE ra.id=customer.reseller_id AND ra.login_user_id=$3)))`
		args = append(args, string(actor.Role), actor.ID)
	}
	err := tx.QueryRowContext(ctx, query, args...).Scan(&req.Domain, &req.Username, &active)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return req, active, err
}

func (s *Service) Workspace(ctx context.Context, actor auth.SessionUser, siteID int64) (Workspace, error) {
	var v Workspace
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, v.Active, err = s.identity(ctx, tx, &actor, siteID)
	if err != nil {
		return v, err
	}
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return v, err
	}
	v.Engine = controlpolicy.StatisticsEngine(policy.Logs)
	v.CanConfigure = policy.Permissions.WebStatistics
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM site_policy_overrides WHERE site_id=$1 AND (policy_patch#>>'{logs,statistics_engine}' IS NOT NULL OR policy_patch#>>'{logs,statistics_enabled}' IS NOT NULL))`, siteID).Scan(&v.Overridden); err != nil {
		return v, err
	}
	v.Settings, err = s.settings(ctx, tx)
	if err != nil {
		return v, err
	}
	v.Enabled = v.Engine == "goaccess" && v.Settings.Enabled
	var generated, requested sql.NullTime
	var data []byte
	var generation, revision int64
	err = tx.QueryRowContext(ctx, `SELECT status,last_error,requested_at,generated_at,summary,report_generation,settings_revision FROM site_web_statistics WHERE site_id=$1`, siteID).Scan(&v.Status, &v.LastError, &requested, &generated, &data, &generation, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		v.Status = "idle"
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.RequestedAt = requested.Time
	v.GeneratedAt = generated.Time
	v.ReportAvailable = v.Enabled && generation > 0 && revision == v.Settings.Revision
	if v.ReportAvailable {
		err = json.Unmarshal(data, &v.Summary)
	}
	return v, err
}

func (s *Service) Queue(ctx context.Context, actor *auth.SessionUser, siteID int64, manual bool) error {
	if s.queue == nil {
		return errors.New("statistics queue unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, active, err := s.identity(ctx, tx, actor, siteID)
	if err != nil {
		return err
	}
	if !active {
		return ErrDisabled
	}
	p, err := controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	settings, err := s.settings(ctx, tx)
	if err != nil {
		return err
	}
	if controlpolicy.StatisticsEngine(p.Logs) != "goaccess" || !settings.Enabled {
		return ErrDisabled
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO site_web_statistics(site_id) VALUES($1) ON CONFLICT DO NOTHING`, siteID)
	if err != nil {
		return err
	}
	var generation int64
	var status string
	var requested sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT generation,status,requested_at FROM site_web_statistics WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&generation, &status, &requested); err != nil {
		return err
	}
	if !RefreshDue(time.Now().UTC(), requested.Time, status, manual, settings.ScheduleHour) {
		return ErrCooldown
	}
	generation++
	_, err = tx.ExecContext(ctx, `UPDATE site_web_statistics SET generation=$2,status='pending',requested_at=now(),last_error='' WHERE site_id=$1`, siteID, generation)
	if err != nil {
		return err
	}
	_, err = s.queue.InsertTx(ctx, tx, GenerateArgs{SiteID: siteID, Generation: generation, SettingsRevision: settings.Revision}, &river.InsertOpts{MaxAttempts: 1})
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Report(ctx context.Context, actor auth.SessionUser, siteID int64) (types.WebStatisticsResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	defer tx.Rollback()
	req, _, err := s.identity(ctx, tx, &actor, siteID)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	var settings Settings
	err = tx.QueryRowContext(ctx, `SELECT enabled,retention_days,schedule_hour,anonymize_ip,revision FROM web_statistics_settings WHERE id=1 FOR SHARE`).Scan(&settings.Enabled, &settings.RetentionDays, &settings.ScheduleHour, &settings.AnonymizeIP, &settings.Revision)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	p, err := controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	if !settings.Enabled || controlpolicy.StatisticsEngine(p.Logs) != "goaccess" {
		return types.WebStatisticsResult{}, ErrNotFound
	}
	err = tx.QueryRowContext(ctx, `SELECT report_generation FROM site_web_statistics WHERE site_id=$1 AND settings_revision=$2 AND report_generation>0 FOR SHARE`, siteID, settings.Revision).Scan(&req.Generation)
	if err != nil {
		return types.WebStatisticsResult{}, ErrNotFound
	}
	req.RetentionDays = settings.RetentionDays
	req.AnonymizeIP = settings.AnonymizeIP
	return s.agent.ReadWebStatistics(ctx, req)
}

func (s *Service) Generate(ctx context.Context, args GenerateArgs) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Match teardown's subscription-before-resource lock order before taking
	// the report lock held across privileged generation.
	if _, err = tx.ExecContext(ctx, `SELECT nakpanel_assert_account_mutable(subscription_id) FROM sites WHERE id=$1`, args.SiteID); err != nil {
		return err
	}
	var generation, retained int64
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT generation,status,report_generation FROM site_web_statistics WHERE site_id=$1 FOR UPDATE`, args.SiteID).Scan(&generation, &status, &retained); errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if generation != args.Generation || status != "pending" {
		return nil
	}
	req, active, err := s.identity(ctx, tx, nil, args.SiteID)
	if err != nil {
		return err
	}
	settings, err := s.settings(ctx, tx)
	if err != nil {
		return err
	}
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, args.SiteID)
	if err != nil {
		return err
	}
	if !active || !settings.Enabled || settings.Revision != args.SettingsRevision || controlpolicy.StatisticsEngine(policy.Logs) != "goaccess" {
		_, err = tx.ExecContext(ctx, `UPDATE site_web_statistics SET status='idle' WHERE site_id=$1`, args.SiteID)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	req.Generation = generation
	req.RetainGeneration = retained
	req.RetentionDays = settings.RetentionDays
	req.AnonymizeIP = settings.AnonymizeIP
	result, runErr := s.agent.GenerateWebStatistics(ctx, req)
	if runErr != nil {
		_, err = tx.ExecContext(ctx, `UPDATE site_web_statistics SET status='failed',last_error='Report generation failed. The last successful report is retained.' WHERE site_id=$1`, args.SiteID)
	} else {
		data, _ := json.Marshal(result.Summary)
		_, err = tx.ExecContext(ctx, `UPDATE site_web_statistics SET status='ready',report_generation=$2,settings_revision=$3,summary=$4,generated_at=now(),last_error='' WHERE site_id=$1`, args.SiteID, generation, settings.Revision, data)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

type GenerateArgs struct {
	SiteID           int64 `json:"site_id"`
	Generation       int64 `json:"generation"`
	SettingsRevision int64 `json:"settings_revision"`
}

func (GenerateArgs) Kind() string { return "generate_web_statistics" }

type GenerateWorker struct {
	river.WorkerDefaults[GenerateArgs]
	Service *Service
}

func (w *GenerateWorker) Work(ctx context.Context, job *river.Job[GenerateArgs]) error {
	return w.Service.Generate(ctx, job.Args)
}
func (w *GenerateWorker) Timeout(*river.Job[GenerateArgs]) time.Duration { return 3 * time.Minute }

type SweepArgs struct{}

func (SweepArgs) Kind() string { return "sweep_web_statistics" }

type SweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	Service *Service
}

func (w *SweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	var hour int
	var enabled bool
	if err := w.Service.db.QueryRowContext(ctx, `SELECT enabled,schedule_hour FROM web_statistics_settings WHERE id=1`).Scan(&enabled, &hour); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	rows, err := w.Service.db.QueryContext(ctx, `SELECT id FROM sites WHERE desired_status='active' ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = w.Service.Queue(ctx, nil, id, false); err != nil && !errors.Is(err, ErrCooldown) && !errors.Is(err, ErrDisabled) {
			return err
		}
	}
	return nil
}

func RefreshDue(now, requested time.Time, status string, manual bool, hour int) bool {
	if requested.IsZero() {
		return true
	}
	if status == "pending" {
		return now.Sub(requested) >= 10*time.Minute
	}
	if manual {
		return now.Sub(requested) >= 15*time.Minute
	}
	now = now.UTC()
	slot := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	if now.Before(slot) {
		slot = slot.AddDate(0, 0, -1)
	}
	return requested.Before(slot)
}
