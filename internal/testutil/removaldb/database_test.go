package removaldb

import "testing"

func TestSiteRemovalRefusesProductionTestDSN(t *testing.T) {
	for _, dsn := range []string{"postgres://postgres@localhost/nakpanel", "dbname=production", "postgres://localhost/nakpanel_removal_test2", "postgres://localhost/postgres", ""} {
		if err := ValidateDSN(dsn); err == nil {
			t.Errorf("accepted non-disposable DSN %q", dsn)
		}
	}
	if err := ValidateDSN("postgres://postgres@localhost/nakpanel_removal_test?sslmode=disable"); err != nil {
		t.Fatal(err)
	}
}
