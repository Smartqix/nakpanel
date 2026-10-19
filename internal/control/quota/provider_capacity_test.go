package quota

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestResellerCapacityIncludesWordPressWithoutPanicking(t *testing.T) {
	for _, test := range []struct {
		name                     string
		limit, existing, request int
		wantExceeded             bool
	}{
		{"first subscription", 5, 0, 2, false},
		{"at capacity", 5, 3, 2, false},
		{"over capacity", 5, 4, 2, true},
		{"existing unlimited exceeds finite", 5, -1, 0, true},
		{"requested unlimited exceeds finite", 5, 0, -1, true},
		{"unlimited provider", -1, -1, -1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			policy := types.HostingPolicy{SchemaVersion: 3, Resources: types.HostingResourcePolicy{MaxWordPressSites: test.limit}}
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery(`SELECT p.max_customers,p.max_subscriptions`).WithArgs(int64(7)).
				WillReturnRows(sqlmock.NewRows([]string{"customers", "subscriptions", "disk", "sites", "subdomains", "aliases", "databases", "traffic", "mailboxes", "ftp", "backups", "backup_storage", "custom", "ssh", "dns", "tls", "allow_backups", "php", "policy"}).
					AddRow(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, true, true, true, true, true, true, raw))
			columns := []string{"customers", "subscriptions"}
			values := []driver.Value{1, 0}
			for _, resource := range []string{"disk", "sites", "subdomains", "aliases", "databases", "traffic", "mailboxes", "ftp", "backups", "backup_storage"} {
				columns = append(columns, resource, resource+"_unlimited")
				values = append(values, 0, false)
			}
			mock.ExpectQuery(`SELECT COUNT\(DISTINCT c.id\)::int`).WithArgs(int64(7), int64(0)).
				WillReturnRows(sqlmock.NewRows(columns).AddRow(values...))
			existing := sqlmock.NewRows([]string{"hosting_policy"})
			if test.existing != 0 {
				policy.Resources.MaxWordPressSites = test.existing
				raw, _ = json.Marshal(policy)
				existing.AddRow(raw)
			}
			mock.ExpectQuery(`SELECT entitlement.hosting_policy`).WithArgs(int64(7), int64(0)).WillReturnRows(existing)
			mock.ExpectRollback()
			policy.Resources.MaxWordPressSites = test.request
			err = validateResellerCapacityTx(context.Background(), tx, 7, 0, types.SubscriptionEntitlements{PlanName: "New", HostingPolicy: policy})
			if errors.Is(err, ErrResellerCapacity) != test.wantExceeded || (err != nil && !test.wantExceeded) {
				t.Fatalf("capacity check = %v, want exceeded=%t", err, test.wantExceeded)
			}
			_ = tx.Rollback()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
