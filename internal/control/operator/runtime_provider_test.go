package operator

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
)

func TestRuntimeProviderRemovalChecksEveryReferenceAndPropagatesDBFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		used  bool
		dbErr bool
	}{
		{"unused", false, false}, {"retained or desired runtime", true, false}, {"database unavailable", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			query := mock.ExpectQuery("SELECT EXISTS").WithArgs("8.4")
			if tc.dbErr {
				query.WillReturnError(errors.New("offline"))
			} else {
				query.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(tc.used))
			}
			used, err := (&Service{db: db}).RuntimeProviderInUse(context.Background(), "nakpanel", "8.4", "8.5")
			if tc.dbErr {
				if err == nil {
					t.Fatal("DB failure authorized removal")
				}
			} else if err != nil || used != tc.used {
				t.Fatalf("used=%v err=%v", used, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRuntimeProviderRemovalBlocksInternalToolWithoutDatabase(t *testing.T) {
	used, err := (&Service{}).RuntimeProviderInUse(context.Background(), "nakpanel", "8.3", "8.3")
	if err != nil || !used {
		t.Fatalf("internal runtime removal allowed: %v %v", used, err)
	}
}
func TestRuntimeProviderRemovalRejectsUnknownProviderVersionOrInternalState(t *testing.T) {
	for _, tc := range [][3]string{{"unknown", "8.3", "8.5"}, {"nakpanel", "../8.3", "8.5"}, {"nakpanel", "8.3", ""}} {
		if _, err := (&Service{}).RuntimeProviderInUse(context.Background(), tc[0], tc[1], tc[2]); err == nil {
			t.Fatalf("invalid state accepted: %v", tc)
		}
	}
}
