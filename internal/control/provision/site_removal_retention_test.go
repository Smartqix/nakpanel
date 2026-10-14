package provision

import (
	"bytes"
	"context"
	"fmt"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"strings"
	"testing"
)

func completeRemovalFixture(t *testing.T) (*SiteRemovalService, types.SiteRemovalOperation) {
	t.Helper()
	db, s, actor, req := removalServiceFixture(t)
	if _, err := db.Exec(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1`, req.SiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status,archive_path,checksum_sha256,database_names) SELECT owner_user_id,customer_id,subscription_id,id,'site',domain,'active','/var/lib/nakpanel/backups/fixture.tar.gz',$2,ARRAY['fixture_db'] FROM sites WHERE id=$1`, req.SiteID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.Digest
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE site_removal_operations SET state='running',stage='finalize',checkpoints=ARRAY['stop_services','remove_hosting','reconcile_shared','surviving-access','surviving-mail','finalize'] WHERE id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	return s, op
}

func TestSiteRemovalRetainsDatabasesAndBackupsPostgreSQL(t *testing.T) {
	s, op := completeRemovalFixture(t)
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := s.db.QueryRow(`SELECT count(*) FROM databases WHERE db_name='fixture_db' AND site_id IS NULL AND subscription_id=$1 AND status='active'`, op.SubscriptionID).Scan(&kept); err != nil || kept != 1 {
		t.Fatal("database not retained", kept, err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM backups WHERE target_name=$1 AND site_id IS NULL AND status='active' AND archive_path<>'' AND checksum_sha256<>''`, op.Domain).Scan(&kept); err != nil || kept != 1 {
		t.Fatal("backup not retained", kept, err)
	}
	s.db.QueryRow("SELECT count(*) FROM sites WHERE id=ANY($1)", pq.Array(removalSelectedSites(op.Snapshot))).Scan(&kept)
	if kept != 0 {
		t.Fatal("removed site rows remain")
	}
	s.db.QueryRow("SELECT count(*) FROM sites WHERE domain='primary.test'").Scan(&kept)
	if kept != 1 {
		t.Fatal("primary site changed")
	}
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal("completed SQL replay", err)
	}
}

func TestSiteRemovalRecoversAfterAgentSuccessPostgreSQL(t *testing.T) {
	s, op := completeRemovalFixture(t)
	if _, err := s.db.Exec(`CREATE FUNCTION fail_removal_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='site.removal_completed' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_removal_completion BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_removal_completion()`); err != nil {
		t.Fatal(err)
	}
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err == nil {
		t.Fatal("audit failure reported success")
	}
	var kept int
	s.db.QueryRow("SELECT count(*) FROM sites WHERE id=$1", op.SiteID).Scan(&kept)
	if kept != 1 {
		t.Fatal("finalization not atomic")
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_removal_completion ON audit_events"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal("SQL recovery", err)
	}
}

func TestSiteRemovalHistoryDoesNotFollowCustomerReassignment(t *testing.T) {
	s, op := completeRemovalFixture(t)
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE subscriptions SET customer_id=(SELECT customer_id FROM subscriptions WHERE id=2) WHERE id=$1", op.SubscriptionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SiteRemovalFor(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, op.ID); err == nil {
		t.Fatal("new customer sees previous customer's removal history")
	}
}

func TestSiteRemovalRetainedBackupRequiresExplicitCurrentTarget(t *testing.T) {
	s, op := completeRemovalFixture(t)
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	repository := NewSQLPhase6Repository(s.db, s.river)
	backupID := op.Snapshot.Backups[0].ID
	if _, err := repository.RestoreBackup(context.Background(), 1, backupID); err == nil || !strings.Contains(err.Error(), "select a website") {
		t.Fatal("detached backup recreated a website or unclear error", err)
	}
	target := removaldb.Site(t, s.db, op.SubscriptionID, op.Domain, nil)
	if _, err := repository.RestoreBackupToSite(context.Background(), 1, backupID, target); err != nil {
		t.Fatal("explicit same-subscription domain restore", err)
	}
	var siteID int64
	if err := s.db.QueryRow("SELECT (args->>'site_id')::bigint FROM river_job WHERE kind='restore_backup'").Scan(&siteID); err != nil || siteID != target {
		t.Fatal("restore does not identify current target", siteID, err)
	}
	if _, err := repository.RestoreBackupToSite(context.Background(), 1, backupID, 1); err == nil {
		t.Fatal("cross-domain restore accepted")
	}
}

func TestSiteRemovalPendingRetainedDatabaseDoesNotStayPending(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	if _, err := db.Exec(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','pending_db','pending_user','pending' FROM sites WHERE id=$1`, req.SiteID); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.Digest
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE site_removal_operations SET state='running',stage='finalize',checkpoints=ARRAY['stop_services','remove_hosting','reconcile_shared','surviving-access','surviving-mail','finalize'] WHERE id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	var status, message string
	if err = db.QueryRow("SELECT status,last_error FROM databases WHERE db_name='pending_db' AND site_id IS NULL").Scan(&status, &message); err != nil || status != "failed" || message == "" {
		t.Fatal("unrecoverable pending database is stranded", status, message, err)
	}
}

func TestSiteRemovalCredentialBackedPendingDatabaseIsRequeuedWithoutSecret(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	var databaseID int64
	if err := db.QueryRow(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','pending_db','pending_user','pending' FROM sites WHERE id=$1 RETURNING id`, req.SiteID).Scan(&databaseID); err != nil {
		t.Fatal(err)
	}
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-only-retained-credential")
	if _, err = serveradmin.NewStore(db, keyring).PutSecret(context.Background(), serveradmin.PutSecretParams{Scope: "database", Name: fmt.Sprintf("provision-%d", databaseID), Plaintext: secret, ActorUserID: actor.ID}); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.Digest
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE site_removal_operations SET state='running',stage='finalize',checkpoints=ARRAY['stop_services','remove_hosting','reconcile_shared','surviving-access','surviving-mail','finalize'] WHERE id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err = db.QueryRow("SELECT args::text FROM river_job WHERE kind='create_database'").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, secret) || bytes.Contains(payload, []byte(`"password"`)) {
		t.Fatal("retained database recovery leaked a credential")
	}
	var status string
	if err = db.QueryRow("SELECT status FROM databases WHERE id=$1 AND site_id IS NULL", databaseID).Scan(&status); err != nil || status != "pending" {
		t.Fatal("recoverable intent not retained", status, err)
	}
}

func TestSiteRemovalClearsDeploymentCyclesAndKeepsSharedSecret(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	var appID, previous, current, outsideID int64
	if err := db.QueryRow(`INSERT INTO php_applications(subscription_id,site_id,php_version) VALUES(1,$1,'8.4') ON CONFLICT(site_id) DO UPDATE SET php_version=EXCLUDED.php_version RETURNING id`, req.SiteID).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number,status) VALUES(1,$1,'test',1,'retired') RETURNING id`, appID).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number,status,previous_deployment_id) VALUES(1,$1,'test',2,'healthy',$2) RETURNING id`, appID, previous).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE php_applications SET active_deployment_id=$2,previous_deployment_id=$3 WHERE id=$1", appID, current, previous); err != nil {
		t.Fatal(err)
	}
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := serveradmin.NewStore(db, keyring).PutSecret(context.Background(), serveradmin.PutSecretParams{Scope: fmt.Sprintf("php.application.%d", appID), Name: "env-db-password", Plaintext: []byte("test-only-shared-secret"), ActorUserID: actor.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,secret_id) VALUES(1,$1,'DB_PASSWORD',$2)`, appID, secret.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO application_instances(subscription_id,site_id,name,runtime,image_ref,endpoint_port) VALUES(1,1,'sibling-app','oci',$1,20010) RETURNING id`, "example.test/image@sha256:"+strings.Repeat("a", 64)).Scan(&outsideID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO application_secret_bindings(application_id,name,secret_id) VALUES($1,'DB_PASSWORD',$2)`, outsideID, secret.ID); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.Digest
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE site_removal_operations SET state='running',stage='finalize',checkpoints=ARRAY['stop_services','remove_hosting','reconcile_shared','surviving-access','surviving-mail','finalize'] WHERE id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal("deployment cycle finalization", err)
	}
	var kept int
	if err = db.QueryRow("SELECT count(*) FROM service_secrets WHERE id=$1", secret.ID).Scan(&kept); err != nil || kept != 1 {
		t.Fatal("shared secret removed", kept, err)
	}
	if err = db.QueryRow("SELECT count(*) FROM php_deployments WHERE application_id=$1", appID).Scan(&kept); err != nil || kept != 0 {
		t.Fatal("deployment cycle remains", kept, err)
	}
}

func TestSiteRemovalSelectedDatabaseRequiresPhysicalCheckpoint(t *testing.T) {
	for _, principalRemoved := range []bool{false, true} {
		t.Run(fmt.Sprint(principalRemoved), func(t *testing.T) {
			db, s, actor, req := removalServiceFixture(t)
			var databaseID int64
			if err := db.QueryRow(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','selected_db','selected_user','active' FROM sites WHERE id=$1 RETURNING id`, req.SiteID).Scan(&databaseID); err != nil {
				t.Fatal(err)
			}
			keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{42}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			secret, err := serveradmin.NewStore(db, keyring).PutSecret(context.Background(), serveradmin.PutSecretParams{Scope: "database", Name: fmt.Sprintf("provision-%d", databaseID), Plaintext: []byte("fixture-db-credential"), ActorUserID: actor.ID})
			if err != nil {
				t.Fatal(err)
			}
			preview, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
			if err != nil {
				t.Fatal(err)
			}
			req.PreviewDigest = preview.Digest
			req.DeleteDatabaseIDs = []int64{databaseID}
			op, err := s.RemoveSiteFor(context.Background(), actor, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE site_removal_operations SET state='running',stage='finalize',checkpoints=ARRAY['stop_services','remove_hosting','reconcile_shared','surviving-access','surviving-mail','finalize'] WHERE id=$1`, op.ID); err != nil {
				t.Fatal(err)
			}
			if err = s.Finalize(context.Background(), op.ID, op.Revision); err == nil {
				t.Fatal("database intent removed before physical checkpoint")
			}
			checkpoint := []string{fmt.Sprintf("database-removed:%d", databaseID)}
			if principalRemoved {
				checkpoint = append(checkpoint, fmt.Sprintf("database-principal-removed:%d", databaseID))
			}
			if _, err = db.Exec(`UPDATE site_removal_operations SET checkpoints=checkpoints||$2::text[] WHERE id=$1`, op.ID, pq.Array(checkpoint)); err != nil {
				t.Fatal(err)
			}
			if err = s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
				t.Fatal(err)
			}
			var count int
			if err = db.QueryRow("SELECT count(*) FROM databases WHERE id=$1", databaseID).Scan(&count); err != nil || count != 0 {
				t.Fatal(count, err)
			}
			want := 1
			if principalRemoved {
				want = 0
			}
			if err = db.QueryRow("SELECT count(*) FROM service_secrets WHERE id=$1", secret.ID).Scan(&count); err != nil || count != want {
				t.Fatal("principal credential retention", count, err)
			}
		})
	}
}
