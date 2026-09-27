package migrations

import (
	"testing"

	"github.com/lib/pq"
)

func TestPhase33WordPressUninstallSchemaPostgreSQL(t *testing.T) {
	phase32Up, _ := migrationSections(t, "20260830000048_phase32_wordpress_toolkit.sql")
	up, down := migrationSections(t, "20260830000049_wordpress_uninstall.sql")
	db := phase30Postgres(t)
	createPhase32WordPressPrerequisites(t, db)
	if _, err := db.Exec(phase32Up); err != nil {
		t.Fatalf("Phase 32 prerequisite Up: %v", err)
	}
	if _, err := db.Exec(`
INSERT INTO wordpress_instances(subscription_id,site_id,database_id,admin_user,admin_email,site_title)
VALUES(10,101,301,'managed','managed@example.test','Managed WordPress');
INSERT INTO wordpress_instances(subscription_id,site_id,admin_user,admin_email,site_title,installed_version,observed_state,convergence_status)
VALUES(20,201,'discovered','discovered@example.test','Discovered WordPress','7.1','healthy','in_sync');
`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 33 Up: %v", err)
	}

	var managed bool
	if err := db.QueryRow(`SELECT database_managed FROM wordpress_instances WHERE database_id IS NOT NULL`).Scan(&managed); err != nil || !managed {
		t.Fatalf("linked Phase 32 instance was not backfilled as managed: managed=%v err=%v", managed, err)
	}
	var discoveredManaged bool
	if err := db.QueryRow(`SELECT database_managed FROM wordpress_instances WHERE database_id IS NULL`).Scan(&discoveredManaged); err != nil || discoveredManaged {
		t.Fatalf("discovered instance became managed: managed=%v err=%v", discoveredManaged, err)
	}
	if _, err := db.Exec(`UPDATE wordpress_instances SET desired_state='absent',observed_state='removed' WHERE database_id IS NULL`); err != nil {
		t.Fatalf("removed tombstone rejected: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO wordpress_operations(
subscription_id,instance_id,kind,backup_requested,database_removal_requested,status)
SELECT subscription_id,id,'uninstall',true,true,'waiting_backup'
FROM wordpress_instances WHERE database_id IS NOT NULL`); err != nil {
		t.Fatalf("uninstall operation rejected: %v", err)
	}
	var databaseNames pq.StringArray
	if err := db.QueryRow(`UPDATE backups SET database_names=ARRAY['wp_s101_deadbeef']::TEXT[] WHERE id=501 RETURNING database_names`).Scan(&databaseNames); err != nil {
		t.Fatalf("backup database manifest rejected: %v", err)
	}
	if len(databaseNames) != 1 || databaseNames[0] != "wp_s101_deadbeef" {
		t.Fatalf("backup database manifest = %v", databaseNames)
	}

	if _, err := db.Exec(down); err != nil {
		t.Fatalf("Phase 33 Down: %v", err)
	}
	var databaseManagedColumn int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns
WHERE table_name='wordpress_instances' AND column_name='database_managed'`).Scan(&databaseManagedColumn); err != nil {
		t.Fatal(err)
	}
	if databaseManagedColumn != 0 {
		t.Fatal("database_managed remains after Phase 33 Down")
	}
}
