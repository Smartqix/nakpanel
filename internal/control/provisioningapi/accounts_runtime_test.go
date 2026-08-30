package provisioningapi

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeAccountRuntimeCapabilities struct {
	value types.RuntimeCapabilities
	err   error
}

func TestAccountCreateRollsBackBeforeMutationWhenNoRuntimeIsReady(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("billing-42").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT public_id FROM billing_accounts`).WithArgs("billing-42").
		WillReturnRows(sqlmock.NewRows([]string{"public_id"}))
	mock.ExpectQuery(`SELECT id,revision,default_php_version,php_allowlist`).WithArgs(nil, "starter").
		WillReturnRows(sqlmock.NewRows([]string{"id", "revision", "default_php_version", "php_allowlist", "site_disk_quota_mb", "php_fpm_max_children", "php_memory_mb"}).
			AddRow(3, 1, "8.4", "8.4,8.5", 512, 3, 128))
	mock.ExpectRollback()

	service := &AccountService{DB: db, Capabilities: fakeAccountRuntimeCapabilities{value: types.RuntimeCapabilities{
		PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}, {Version: "8.5", Ready: false}},
	}}}
	_, created, err := service.Create(context.Background(), 9, createAccountRequest{
		ExternalRef: "billing-42", Provider: "admin", Plan: "starter",
		Email: "owner@example.test", Domain: "example.test",
	})
	if err == nil || created {
		t.Fatalf("Create = created %v, error %v; want fail closed", created, err)
	}
	var accountErr *accountError
	if !errors.As(err, &accountErr) || accountErr.code != "runtime_unavailable" {
		t.Fatalf("Create error = %T %v; want runtime_unavailable", err, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func (f fakeAccountRuntimeCapabilities) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	return f.value, f.err
}

func TestAccountServiceSelectsReadyPermittedPHP(t *testing.T) {
	plan := selectedPlan{PHPAllowlist: "8.4,8.5,8.3", DefaultPHP: "8.4"}
	for _, test := range []struct {
		name     string
		allow    string
		runtimes []types.PHPRuntimeCapability
		want     string
		wantErr  bool
	}{
		{name: "prefer ready 8.4", runtimes: []types.PHPRuntimeCapability{{Version: "8.5", Ready: true}, {Version: "8.4", Ready: true}}, want: "8.4"},
		{name: "fall back to ready 8.5", runtimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}, {Version: "8.5", Ready: true}}, want: "8.5"},
		{name: "exclude ready but unpermitted 8.4", allow: "8.5", runtimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true}, {Version: "8.5", Ready: true}}, want: "8.5"},
		{name: "fail closed with no ready permitted runtime", runtimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}, {Version: "8.5", Ready: false}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := plan
			if test.allow != "" {
				selected.PHPAllowlist = test.allow
			}
			service := &AccountService{Capabilities: fakeAccountRuntimeCapabilities{value: types.RuntimeCapabilities{PHPRuntimes: test.runtimes}}}
			got, err := service.readyPHPVersion(context.Background(), selected)
			if test.wantErr {
				if err == nil || got != "" {
					t.Fatalf("ready PHP = %q, %v; want fail closed", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("ready PHP = %q, %v; want %q", got, err, test.want)
			}
		})
	}

	service := &AccountService{Capabilities: fakeAccountRuntimeCapabilities{err: errors.New("agent unavailable")}}
	if got, err := service.readyPHPVersion(context.Background(), plan); err == nil || got != "" {
		t.Fatalf("capability failure returned %q, %v; want fail closed", got, err)
	}
}
