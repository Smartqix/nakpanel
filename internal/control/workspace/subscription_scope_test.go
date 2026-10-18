package workspace

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

func TestSubscriptionServicesWhereNarrowsRoleScope(t *testing.T) {
	id := int64(42)
	for _, tc := range []struct {
		role  auth.Role
		where string
		args  []any
	}{
		{auth.RoleAdmin, "(TRUE) AND sub.id = $1", []any{id}},
		{auth.RoleReseller, "(reseller.login_user_id=$1) AND sub.id = $2", []any{int64(7), id}},
		{auth.RoleClient, "(customer.login_user_id=$1) AND sub.id = $2", []any{int64(7), id}},
	} {
		where, args, err := subscriptionServicesScope(auth.SessionUser{ID: 7, Role: tc.role}, &id)
		if err != nil || where != tc.where || !reflect.DeepEqual(args, tc.args) {
			t.Fatalf("%s: %s %#v %v", tc.role, where, args, err)
		}
		where, args, err = subscriptionServicesScope(auth.SessionUser{ID: 7, Role: tc.role}, nil)
		original, originalArgs, _ := subscriptionScope(auth.SessionUser{ID: 7, Role: tc.role})
		if err != nil || where != original || !reflect.DeepEqual(args, originalArgs) {
			t.Fatal("unscoped role changed")
		}
	}
	if _, _, err := subscriptionServicesScope(auth.SessionUser{Role: "unknown"}, &id); err == nil {
		t.Fatal("unsupported role accepted")
	}
}

func TestEveryServiceQueryIncludesSubscriptionAndRoleScope(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.MatchExpectationsInOrder(false)
			id := int64(42)
			where, _, _ := subscriptionServicesScope(auth.SessionUser{ID: 7, Role: role}, &id)
			tables := []string{"subscription_system_accounts", "sites", "sftp_access_identities", "scheduled_tasks", "ftp_accounts", "git_repositories", "git_deployments", "protected_directories", "valkey_instances", "staging_operations", "mail_domains", "mailboxes", "mail_aliases", "webmail_hosts", "application_instances", "application_generations", "scheduled_task_runs", "site_usage_current", "application_presets"}
			for _, table := range tables {
				query := mock.ExpectQuery(`(?s)FROM ` + table + ` .*WHERE ` + regexp.QuoteMeta(where))
				if role == auth.RoleAdmin {
					query.WithArgs(id)
				} else {
					query.WithArgs(int64(7), id)
				}
				rows := sqlmock.NewRows([]string{"unused"})
				if table == "sftp_access_identities" {
					rows = sqlmock.NewRows([]string{"id", "subscription_id", "name", "relative_root", "enabled"}).AddRow(1, id, "owned", "public_html", true)
				}
				query.WillReturnRows(rows)
			}
			data, err := NewStore(db).ListSubscriptionServicesFor(context.Background(), auth.SessionUser{ID: 7, Role: role}, id)
			if err != nil {
				t.Fatal(err)
			}
			if len(data.SFTP) != 1 || data.SFTP[0].SubscriptionID != id {
				t.Fatalf("services: %#v", data.SFTP)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
