package webstatistics

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRefreshDue(t *testing.T) {
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		requested    time.Time
		status       string
		manual, want bool
	}{
		{"never", time.Time{}, "idle", false, true},
		{"manual cooldown", now.Add(-14 * time.Minute), "ready", true, false},
		{"manual available", now.Add(-15 * time.Minute), "ready", true, true},
		{"manual last evening does not skip daily", now.Add(-8 * time.Hour), "ready", false, true},
		{"already scheduled today", now.Add(-30 * time.Minute), "ready", false, false},
		{"stale pending", now.Add(-11 * time.Minute), "pending", false, true},
		{"running", now.Add(-9 * time.Minute), "pending", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RefreshDue(now, tc.requested, tc.status, tc.manual, 3); got != tc.want {
				t.Fatalf("due=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestMigrationPreservesTeardownGuard(t *testing.T) {
	data, err := os.ReadFile("../../../migrations/20260908000050_phase34_web_statistics.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"account.provisioning_state IN ('terminating','terminated')", "site_web_statistics_account_teardown_guard", "PERFORM nakpanel_assert_account_mutable(subscription_id_value)"} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	if strings.Contains(text, "DISABLE TRIGGER") || strings.Contains(text, "SET nakpanel.account_teardown") {
		t.Fatal("migration bypasses teardown guard")
	}
}

type statisticsAgent struct {
	calls int
	err   error
}

func (a *statisticsAgent) GenerateWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	a.calls++
	return types.WebStatisticsResult{Summary: types.WebStatisticsSummary{Requests: 123}}, a.err
}
func (a *statisticsAgent) ReadWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	a.calls++
	return types.WebStatisticsResult{}, nil
}
func (a *statisticsAgent) WebStatisticsStatus(context.Context) (types.WebStatisticsStatus, error) {
	return types.WebStatisticsStatus{}, nil
}

func expectStatisticsPolicy(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT site.subscription_id").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "patch"}).AddRow(9, `{}`))
	policy := controlpolicy.DefaultFromEntitlements(types.SubscriptionEntitlements{})
	policy.Logs = types.LogsPreset{StatisticsEngine: "goaccess", StatisticsEnabled: true}
	raw, _ := json.Marshal(policy)
	columns := strings.Split("subscription_id,plan_name,disk_mb,max_sites,max_databases,bandwidth_mb,max_mailboxes,allow_ssh,allow_dns,backup_retention_days,php_allowlist,php_fpm_max_children,php_memory_mb,site_disk_quota_mb,max_backups,backup_storage_mb,source_revision,overuse_policy,disk_warning_percent,traffic_warning_percent,max_subdomains,max_domain_aliases,max_ftp_accounts,validity_days,hosting_enabled,default_php_version,allow_tls,allow_backups,allow_php_settings,service_presets,hosting_policy", ",")
	mock.ExpectQuery("SELECT subscription_id,plan_name").WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows(columns).AddRow(9, "plan", 0, 0, 0, 0, 0, false, false, 0, "", 0, 0, 0, 0, 0, 1, "block", 80, 80, 0, 0, 0, 0, true, "", false, false, false, `{}`, raw))
	mock.ExpectQuery("SELECT e.hosting_policy").WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"policy", "patch"}).AddRow(raw, `{}`))
}

func TestGenerationFailureRetainsLastGoodReport(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			agent := &statisticsAgent{}
			if failed {
				agent.err = errors.New("secret host path")
			}
			mock.ExpectBegin()
			mock.ExpectExec("SELECT nakpanel_assert_account_mutable").WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("SELECT generation,status,report_generation").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"generation", "status", "report_generation"}).AddRow(3, "pending", 1))
			mock.ExpectQuery("SELECT site.domain,site.username").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"domain", "username", "active"}).AddRow("example.test", "example", true))
			mock.ExpectQuery("SELECT enabled,retention_days").WillReturnRows(sqlmock.NewRows([]string{"enabled", "days", "hour", "anon", "revision"}).AddRow(true, 30, 3, true, 1))
			expectStatisticsPolicy(mock)
			if failed {
				mock.ExpectExec("UPDATE site_web_statistics SET status='failed',last_error='").WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				mock.ExpectExec("UPDATE site_web_statistics SET status='ready',report_generation=").WithArgs(int64(7), int64(3), int64(1), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectCommit()
			if err = New(db, agent, nil).Generate(context.Background(), GenerateArgs{SiteID: 7, Generation: 3, SettingsRevision: 1}); err != nil {
				t.Fatal(err)
			}
			if agent.calls != 1 {
				t.Fatalf("agent calls=%d", agent.calls)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrossTenantReportNeverCallsAgent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &statisticsAgent{}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT site.domain,site.username.*customer.login_user_id").WithArgs(int64(7), "client", int64(999)).WillReturnRows(sqlmock.NewRows([]string{"domain", "username", "active"}))
	mock.ExpectRollback()
	_, err = New(db, agent, nil).Report(context.Background(), auth.SessionUser{ID: 999, Role: auth.RoleClient}, 7)
	if !errors.Is(err, ErrNotFound) || agent.calls != 0 {
		t.Fatalf("error=%v calls=%d", err, agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSettingsAuthorizationAndValidation(t *testing.T) {
	s := New(nil, nil, nil)
	if err := s.SaveSettings(context.Background(), auth.SessionUser{Role: auth.RoleClient}, Settings{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("client settings: %v", err)
	}
	if err := s.SaveSettings(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, Settings{RetentionDays: 91}); err == nil {
		t.Fatal("invalid retention accepted")
	}
}
func TestStaleGenerationNeverCallsAgent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT nakpanel_assert_account_mutable").WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT generation,status,report_generation").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"generation", "status", "report_generation"}).AddRow(3, "pending", 1))
	mock.ExpectRollback()
	s := New(db, nil, nil)
	if err = s.Generate(context.Background(), GenerateArgs{SiteID: 7, Generation: 2}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSettingsPrivacyRevisionOnlyChangesForReportPolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("revision=revision\\+CASE WHEN retention_days<>\\$2 OR anonymize_ip<>\\$4 THEN 1 ELSE 0 END").WithArgs(true, 30, 4, true).WillReturnResult(sqlmock.NewResult(0, 1))
	if err = New(db, nil, nil).SaveSettings(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, Settings{Enabled: true, RetentionDays: 30, ScheduleHour: 4, AnonymizeIP: true}); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
