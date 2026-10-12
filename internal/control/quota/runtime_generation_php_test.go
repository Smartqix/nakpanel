package quota

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestRuntimeGenerationUsesSelectedPHP(t *testing.T) {
	for _, test := range []struct{ name, desired, current, want, state string }{
		{"desired", "8.5", "8.3", "8.5", "active"},
		{"current fallback", "", "8.3", "8.3", "active"},
		{"policy fallback", "", "", "8.4", "active"},
		{"suspended retired current", "8.3", "8.5", "8.5", "suspended"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			domain := types.SubscriptionDomain{SiteID: 7, State: test.state, DesiredPHPVersion: test.desired, CurrentPHPVersion: test.current, Policy: types.HostingPolicy{PHP: types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.3", "8.4", "8.5"}}}}
			if test.state == "suspended" {
				domain.Policy.PHP.AllowedVersions = []string{"8.4"}
			}
			runtimePolicy := domain.Policy
			runtimePolicy.PHP.DefaultVersion = test.want
			policyJSON, _ := json.Marshal(runtimePolicy)
			webJSON, _ := json.Marshal(runtimePolicy.Web)
			phpJSON, _ := json.Marshal(runtimePolicy.PHP)
			nginxHash := fmt.Sprintf("%x", sha256.Sum256(webJSON))
			phpHash := fmt.Sprintf("%x", sha256.Sum256(phpJSON))
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT id FROM site_runtime_generations").WithArgs(int64(7), nginxHash, phpHash).WillReturnError(sql.ErrNoRows)
			mock.ExpectQuery("INSERT INTO site_runtime_generations").WithArgs(int64(7), test.want, policyJSON, nginxHash, phpHash).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(11))
			mock.ExpectQuery("SELECT status FROM site_runtime_generations").WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("candidate"))
			mock.ExpectCommit()
			ids, err := prepareRuntimeGenerations(context.Background(), db, []types.SubscriptionDomain{domain})
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 1 || ids[0] != 11 {
				t.Fatalf("generation IDs: %v", ids)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeGenerationDoesNotClaimManagedApplicationRuntime(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domain := types.SubscriptionDomain{SiteID: 7, State: "active", Policy: types.HostingPolicy{PHP: types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.4"}}}}
	if err := json.Unmarshal([]byte(`{"hosting_mode":"managed","active_deployment_id":91}`), &domain); err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectCommit()
	ids, err := prepareRuntimeGenerations(context.Background(), db, []types.SubscriptionDomain{domain})
	if err != nil || len(ids) != 0 {
		t.Fatalf("generic convergence claimed managed generation: %v, %v", ids, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
