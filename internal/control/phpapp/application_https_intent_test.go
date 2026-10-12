package phpapp

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestApplicationSelectCarriesTrustedHTTPSRedirectIntent(t *testing.T) {
	if !strings.Contains(applicationSelect, "site.desired_https_redirect") {
		t.Fatal("managed PHP application query omits site HTTPS redirect intent")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	values := []driver.Value{int64(7), int64(4), int64(3), int64(5), "npaccount", "example.test", "managed", "8.4", int64(1), "main", "custom", "public", "/up", []byte(`[]`), false, false, false, 3, "active", "healthy", int64(22), int64(0), int64(2), int64(2), "in_sync", "", "", "active", "active", "active", true, true}
	columns := make([]string, len(values))
	for i := range columns {
		columns[i] = fmt.Sprintf("column_%d", i)
	}
	mock.ExpectQuery(`SELECT application.id`).WillReturnRows(sqlmock.NewRows(columns).AddRow(values...))
	record, err := scanApplication(db.QueryRowContext(context.Background(), applicationSelect))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record.spec)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(encoded, &spec); err != nil {
		t.Fatal(err)
	}
	if spec["https_redirect"] != true {
		t.Fatal("server-derived HTTPS intent did not reach agent application spec")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
