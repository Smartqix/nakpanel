# Phase 33 Safe WordPress Uninstall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a recoverable, auditable WordPress uninstall workflow that removes Toolkit-managed WordPress files and, when safely requested, its dedicated database without deleting the hosted domain or unrelated resources.

**Architecture:** The HTTP layer accepts only uninstall choices and an exact-domain confirmation. The control plane reserves a revision-fenced tombstone operation, gates optional database deletion on a durable recovery backup, and runs identifier-only River jobs. The privileged agent independently derives the site root, atomically quarantines WordPress, removes only a validated Toolkit database, restores the Nakpanel placeholder, and supports idempotent retry and cleanup.

**Tech Stack:** Go 1.23, PostgreSQL/goose, River, stdlib HTTP, templ, embedded CSS/JavaScript, WP-CLI 2.12.0, MariaDB, Ubuntu 24.04.

**Spec:** `docs/superpowers/specs/2026-08-30-wordpress-uninstall-design.md`

## Global Constraints

- Uninstall removes WordPress but preserves the domain, subscription, TLS, DNS, PHP configuration, mail, unrelated databases, and backups.
- A Toolkit-managed database may be deleted only after a completed same-site recovery backup proves it contains that database.
- Discovered, external, unlinked, and ambiguously owned databases are always preserved.
- Browser forms never supply filesystem paths, Linux users, database identifiers, service names, owners, or plan limits.
- River arguments contain only numeric IDs and desired revisions.
- Database and WordPress credentials never appear in River arguments, audit metadata, HTML, JSON, result payloads, command output, or logs.
- The agent derives paths and revalidates WordPress identity, database provenance, identifiers, symlink safety, and operation markers.
- Cross-tenant lookups return `404`; every mutation requires CSRF and an audit event.
- Removed instances remain as tombstones, release WordPress allocation only after convergence, and can be reinstalled without erasing history.
- Existing Phase 32 install, update, hardening, password-reset, maintenance, discovery, and detach behavior remains compatible.

---

### Task 1: Schema, States, And Typed Contracts

**Files:**
- Create: `migrations/20260830000049_wordpress_uninstall.sql`
- Create: `migrations/phase33_postgres_test.go`
- Modify: `migrations/phase32_postgres_test.go`
- Modify: `internal/types/wordpress.go`
- Modify: `internal/types/wordpress_test.go`
- Modify: `internal/control/wordpress/models.go`
- Modify: `internal/control/wordpress/store.go`
- Test: `internal/control/wordpress/store_test.go`

**Interfaces:**
- Consumes: Phase 32 `wordpress_instances`, `wordpress_operations`, `backups`, `types.WordPressOperationReq`, and `types.WordPressOperationResult`.
- Produces: `types.WordPressActionUninstall`, `types.WordPressRemovalSpec`, `types.WordPressRemovalResult`, `UninstallInput`, managed-database provenance, absent/removed tombstone states, and backup database manifests used by later tasks.

- [ ] **Step 1: Write the failing PostgreSQL migration test**

Add `TestPhase33WordPressUninstallSchemaPostgreSQL` that applies Phase 32, creates one managed and one discovered instance, applies Phase 33, and proves the new constraints:

```go
func TestPhase33WordPressUninstallSchemaPostgreSQL(t *testing.T) {
    up, down := migrationSections(t, "20260830000049_wordpress_uninstall.sql")
    db := phase30Postgres(t)
    phase32Up, _ := migrationSections(t, "20260830000048_phase32_wordpress_toolkit.sql")
    createPhase32WordPressPrerequisites(t, db)
    if _, err := db.Exec(phase32Up); err != nil {
        t.Fatalf("Phase 32 prerequisite Up: %v", err)
    }
    seedPhase33WordPressInstances(t, db)
    if _, err := db.Exec(up); err != nil {
        t.Fatalf("Phase 33 Up: %v", err)
    }
    var managed bool
    if err := db.QueryRow(`SELECT database_managed FROM wordpress_instances WHERE database_id IS NOT NULL`).Scan(&managed); err != nil || !managed {
        t.Fatalf("linked Phase 32 instance was not backfilled as managed: managed=%v err=%v", managed, err)
    }
    if _, err := db.Exec(`UPDATE wordpress_instances SET desired_state='absent',observed_state='removed' WHERE database_id IS NULL`); err != nil {
        t.Fatalf("removed tombstone rejected: %v", err)
    }
    if _, err := db.Exec(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,backup_requested,database_removal_requested,status)
        SELECT subscription_id,id,'uninstall',true,true,'waiting_backup' FROM wordpress_instances LIMIT 1`); err != nil {
        t.Fatalf("uninstall operation rejected: %v", err)
    }
    if _, err := db.Exec(down); err != nil {
        t.Fatalf("Phase 33 Down: %v", err)
    }
}
```

Move the prerequisite DDL currently embedded in `phase32_postgres_test.go` into `createPhase32WordPressPrerequisites(t, db)` without changing the SQL, then call the helper from both Phase 32 and Phase 33 tests. `seedPhase33WordPressInstances` inserts one instance linked to its same-site database and one unlinked discovered instance.

- [ ] **Step 2: Run the migration test and verify the expected failure**

Run:

```bash
go test ./migrations -run TestPhase33WordPressUninstallSchemaPostgreSQL -count=1
```

Expected: FAIL because `20260830000049_wordpress_uninstall.sql` and the new columns/states do not exist.

- [ ] **Step 3: Add the migration with reversible constraints**

Implement an Up migration that drops and recreates the existing checks without weakening unrelated values:

```sql
ALTER TABLE wordpress_instances ADD COLUMN database_managed BOOLEAN NOT NULL DEFAULT false;
UPDATE wordpress_instances SET database_managed = true WHERE database_id IS NOT NULL;

ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_desired_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_desired_state_check
    CHECK (desired_state IN ('present','detached','absent'));
ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_observed_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_observed_state_check
    CHECK (observed_state IN ('pending','installing','healthy','failed','missing','detached','removing','removed'));

ALTER TABLE wordpress_operations ADD COLUMN backup_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE wordpress_operations ADD COLUMN database_removal_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE wordpress_operations DROP CONSTRAINT wordpress_operations_kind_check;
ALTER TABLE wordpress_operations ADD CONSTRAINT wordpress_operations_kind_check
    CHECK (kind IN ('install','discover','refresh','update','verify','harden','maintenance','password_reset','settings','detach','uninstall'));

ALTER TABLE backups ADD COLUMN database_names TEXT[] NOT NULL DEFAULT '{}';
```

The Down migration must remove Phase 33 uninstall rows before restoring Phase 32 checks, convert `absent`/`removed` rows to a Phase 32-safe failed state, remove the three added columns, and leave Phase 32 data valid.

- [ ] **Step 4: Add typed request and result contracts**

Extend `internal/types/wordpress.go` with these exact contracts:

```go
const WordPressActionUninstall WordPressAction = "uninstall"

type WordPressRemovalSpec struct {
    DeleteDatabase bool   `json:"delete_database"`
    DatabaseName   string `json:"database_name,omitempty"`
    DatabaseUser   string `json:"database_user,omitempty"`
    Finalize       bool   `json:"finalize,omitempty"`
}

type WordPressRemovalResult struct {
    FilesRemoved      bool  `json:"files_removed"`
    DatabaseRemoved   bool  `json:"database_removed"`
    DatabasePreserved bool  `json:"database_preserved"`
    BackupID          int64 `json:"backup_id,omitempty"`
}
```

Add `Removal *WordPressRemovalSpec` to `WordPressOperationReq` and `Removal *WordPressRemovalResult` to `WordPressOperationResult`, both with `json:",omitempty"`. Add JSON round-trip tests proving no password, path, or secret field exists.

- [ ] **Step 5: Extend control-plane models and SQL scans**

Add these fields without changing existing names:

```go
type Instance struct {
    // existing fields
    DatabaseManaged bool
}

type Operation struct {
    // existing fields
    BackupRequested         bool
    DatabaseRemovalRequested bool
}

type UninstallInput struct {
    CreateBackup   bool
    DeleteDatabase bool
    ConfirmDomain  string
}
```

Update `instanceSelect`, `loadInstance`, operation inserts/selects/scans, and test fixtures in one pass. Change `wordpressUsageCountSQL` to count every instance whose `observed_state <> 'removed'`, while retaining the existing failed-discovery exclusion.

- [ ] **Step 6: Run focused tests and commit**

Run:

```bash
go test ./migrations ./internal/types ./internal/control/wordpress -count=1
git diff --check
```

Expected: PASS.

Commit:

```bash
git add migrations/20260830000049_wordpress_uninstall.sql migrations/phase33_postgres_test.go migrations/phase32_postgres_test.go internal/types/wordpress.go internal/types/wordpress_test.go internal/control/wordpress/models.go internal/control/wordpress/store.go internal/control/wordpress/store_test.go
git commit -m "feat: add WordPress uninstall state contracts"
```

---

### Task 2: Durable Backup Coverage Evidence

**Files:**
- Modify: `internal/control/provision/phase6_jobs.go`
- Modify: `internal/control/provision/phase6_repository.go`
- Modify: `internal/control/provision/phase6_jobs_test.go`
- Modify: `internal/control/provision/repository_test.go`

**Interfaces:**
- Consumes: `CreateBackupArgs.Databases`, `types.CreateBackupResult`, and `backups.database_names` from Task 1.
- Produces: `MarkBackupActive(context.Context, int64, types.CreateBackupResult, []string) error` and an immutable database manifest used by the uninstall worker.

- [ ] **Step 1: Write failing backup manifest tests**

Add a worker test that captures the database list passed to the status store:

```go
func TestCreateBackupWorkerPersistsDatabaseCoverage(t *testing.T) {
    store := &recordingPhase6Store{}
    worker := NewCreateBackupWorker(fakeBackupAgent{result: types.CreateBackupResult{
        ArchivePath: "/var/lib/nakpanel/backups/site.tar.zst",
        SizeBytes: 4096,
        SHA256: strings.Repeat("a", 64),
    }}, store)
    job := &river.Job[CreateBackupArgs]{Args: CreateBackupArgs{
        BackupID: 41, SiteID: 7, SubscriptionID: 3,
        Databases: []string{"wp_s7_deadbeef"},
    }}
    if err := worker.Work(context.Background(), job); err != nil {
        t.Fatal(err)
    }
    if !slices.Equal([]string{"wp_s7_deadbeef"}, store.databaseNames) {
        t.Fatalf("database coverage mismatch: %v", store.databaseNames)
    }
}
```

Add a repository expectation that `MarkBackupActive` writes a PostgreSQL text array and does not accept browser input.

- [ ] **Step 2: Run the focused tests and confirm the interface failure**

Run:

```bash
go test ./internal/control/provision -run 'TestCreateBackupWorkerPersistsDatabaseCoverage|TestMarkBackupActive' -count=1
```

Expected: FAIL because `MarkBackupActive` does not accept or persist database names.

- [ ] **Step 3: Change the status-store interface and persistence**

Change the interface and worker call to:

```go
type Phase6StatusStore interface {
    MarkBackupActive(context.Context, int64, types.CreateBackupResult, []string) error
    // retain the existing methods unchanged
}

if err := w.store.MarkBackupActive(ctx, job.Args.BackupID, result, append([]string(nil), job.Args.Databases...)); err != nil {
    return err
}
```

Persist a sorted, deduplicated copy with `pq.Array(databaseNames)`:

```go
_, err := s.db.ExecContext(ctx, `UPDATE backups SET status='active',archive_path=$2,size_bytes=$3,
checksum_sha256=$4,database_names=$5,last_error='',updated_at=now() WHERE id=$1`,
    id, result.ArchivePath, result.SizeBytes, result.SHA256, pq.Array(databaseNames))
```

Update every fake implementation explicitly; do not weaken interfaces with variadic arguments.

- [ ] **Step 4: Run provisioning and backup regression tests**

Run:

```bash
go test ./internal/control/provision ./internal/backup ./internal/agent/ops -count=1
```

Expected: PASS, including existing create/restore behavior.

- [ ] **Step 5: Commit the backup manifest change**

```bash
git add internal/control/provision/phase6_jobs.go internal/control/provision/phase6_repository.go internal/control/provision/phase6_jobs_test.go internal/control/provision/repository_test.go
git commit -m "feat: persist backup database coverage"
```

---

### Task 3: Agent-Side Atomic WordPress Removal

**Files:**
- Create: `internal/agent/ops/wordpress_uninstall.go`
- Create: `internal/agent/ops/wordpress_uninstall_test.go`
- Modify: `internal/agent/ops/wordpress.go`
- Modify: `internal/agent/ops/create_database.go`
- Modify: `cmd/agent/main.go`

**Interfaces:**
- Consumes: `types.WordPressActionUninstall`, `types.WordPressRemovalSpec`, existing `WordPressProvisioner.documentRoot`, safe-open helpers, placeholder conventions, and MariaDB DSN construction.
- Produces: idempotent `uninstallWordPress` and `finalizeWordPressRemoval`, a narrow `WordPressDatabaseRemover`, root-owned markers, and bounded `types.WordPressRemovalResult`.

- [ ] **Step 1: Write failing filesystem safety tests**

Create table-driven tests covering a recognized WordPress root, arbitrary replacement content, symlinked roots, missing markers, retries, and finalization. The successful case must assert the old tree is no longer under `public_html`, the generated placeholder is present, and the result contains no path:

```go
func TestUninstallWordPressAtomicallyReplacesRecognizedRoot(t *testing.T) {
    fixture := newWordPressRemovalFixture(t)
    result, err := fixture.provisioner.RunWordPress(context.Background(), fixture.request(false))
    if err != nil {
        t.Fatal(err)
    }
    if result.Removal == nil || !result.Removal.FilesRemoved || !result.Removal.DatabasePreserved {
        t.Fatalf("unexpected removal result: %#v", result.Removal)
    }
    assertNakpanelPlaceholder(t, fixture.documentRoot)
    encoded, _ := json.Marshal(result)
    if bytes.Contains(encoded, []byte(fixture.documentRoot)) {
        t.Fatal("agent result exposed a filesystem path")
    }
}
```

Add explicit tests named `TestUninstallWordPressRejectsSymlinkRoot`, `TestUninstallWordPressRejectsArbitraryContent`, `TestUninstallWordPressRetryUsesMatchingMarker`, and `TestFinalizeWordPressRemovalRejectsWrongRevision`.

- [ ] **Step 2: Write failing MariaDB removal tests**

Use a fake `SQLExecutor` to assert exactly quoted statements and rejection before execution:

```go
func TestMariaDBWordPressRemoverRejectsIdentifierInjection(t *testing.T) {
    exec := &recordingSQLExecutor{}
    remover := NewMariaDBWordPressRemover(exec)
    _, err := remover.Remove(context.Background(), 9, "wp_s9_ok`; DROP DATABASE mysql;--", "wp_u9_deadbeef")
    if err == nil || len(exec.queries) != 0 {
        t.Fatalf("unsafe identifier reached SQL: err=%v queries=%v", err, exec.queries)
    }
}
```

Cover database already absent, user already absent, database drop failure before mutation, user drop failure after database removal, and state inspection.

- [ ] **Step 3: Run the new agent tests and verify they fail**

Run:

```bash
go test ./internal/agent/ops -run 'Test(UninstallWordPress|FinalizeWordPress|MariaDBWordPress)' -count=1
```

Expected: FAIL because the teardown provisioner does not exist.

- [ ] **Step 4: Implement narrow database and marker interfaces**

Add these interfaces in `wordpress_uninstall.go`:

```go
type WordPressDatabaseState struct {
    DatabasePresent bool
    UserPresent     bool
}

type WordPressDatabaseRemover interface {
    Inspect(context.Context, int64, string, string) (WordPressDatabaseState, error)
    Remove(context.Context, int64, string, string) (WordPressDatabaseState, error)
}
```

Extend `WordPressProvisionerOptions` with `DatabaseRemover WordPressDatabaseRemover`. Production wiring uses a lazy MariaDB implementation backed by `NAKPANEL_MARIADB_DSN`. Validation must require `wp_s<siteID>_<8 hex>` and `wp_u<siteID>_<8 hex>`, quote identifiers internally, and use no shell command or browser-supplied SQL.

The production constructor is `func NewLazyMariaDBWordPressRemover(dsn string) WordPressDatabaseRemover`; it uses `DefaultMariaDBDSN()` when the environment value is empty. Wire it into `cmd/agent/main.go` through `WordPressProvisionerOptions.DatabaseRemover`.

- [ ] **Step 5: Implement atomic quarantine and idempotent markers**

Use an agent-derived root-owned state directory under the domain. The marker JSON contains only numeric identity and state:

```go
type wordpressRemovalMarker struct {
    OperationID      int64 `json:"operation_id"`
    InstanceID       int64 `json:"instance_id"`
    DesiredRevision  int64 `json:"desired_revision"`
    FilesQuarantined bool  `json:"files_quarantined"`
    DatabaseRemoved  bool  `json:"database_removed"`
}
```

Perform all validation before renaming. Create a sibling candidate placeholder, fsync it, rename `public_html` to the deterministic quarantine, rename the candidate into `public_html`, and fsync the parent. On pre-deletion database failure, reverse the two renames. Never follow symlinks or recursively delete a path that was not derived and marker-matched.

- [ ] **Step 6: Dispatch uninstall and finalize through the existing typed WordPress RPC**

Extend `RunWordPress`:

```go
case types.WordPressActionUninstall:
    if req.Removal == nil {
        return types.WordPressOperationResult{}, errors.New("WordPress removal specification is required")
    }
    if req.Removal.Finalize {
        return p.finalizeWordPressRemoval(ctx, req)
    }
    return p.uninstallWordPress(ctx, req)
```

Do not add a generic database-delete RPC. Keep deletion available only inside the validated WordPress operation.

- [ ] **Step 7: Run agent tests and commit**

Run:

```bash
go test ./internal/agent/ops ./internal/agent/rpc ./internal/control/agentclient ./cmd/agent -count=1
go test -race ./internal/agent/ops -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/agent/ops/wordpress_uninstall.go internal/agent/ops/wordpress_uninstall_test.go internal/agent/ops/wordpress.go internal/agent/ops/create_database.go cmd/agent/main.go
git commit -m "feat: add atomic WordPress removal agent"
```

---

### Task 4: Uninstall Reservation And Manager Orchestration

**Files:**
- Modify: `internal/control/wordpress/models.go`
- Modify: `internal/control/wordpress/manager.go`
- Modify: `internal/control/wordpress/store.go`
- Modify: `internal/control/wordpress/manager_test.go`
- Modify: `internal/control/wordpress/store_test.go`

**Interfaces:**
- Consumes: `UninstallInput`, central `AccessPolicy`, `Provisioner.CreateBackupForSubscription`, Phase 33 schema, and existing River inserter.
- Produces: `Manager.Uninstall`, `ManagerStore.ReserveUninstall`, safe reservation rollback, backup attachment, and tombstone-aware `ReserveInstall`.

- [ ] **Step 1: Write manager validation and authorization tests**

Add tests for exact-domain confirmation, cross-tenant `ErrNotFound`, suspended-client denial, provider cleanup, disabled entitlement cleanup, external database preservation, managed database requiring backup, backup provisioning failure, and successful identifier-only enqueue:

```go
func TestUninstallRequiresBackupForManagedDatabaseRemoval(t *testing.T) {
    store := &fakeStore{identity: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test"}}
    manager := NewManager(store, allowAccessPolicy{}, &fakeProvisioner{})
    _, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
        DeleteDatabase: true,
        ConfirmDomain:  "example.test",
    })
    if !errors.Is(err, ErrInvalidInput) || store.reserveUninstallCalls != 0 {
        t.Fatalf("unsafe uninstall reserved: err=%v calls=%d", err, store.reserveUninstallCalls)
    }
}
```

- [ ] **Step 2: Write SQL reservation tests**

Use PostgreSQL-backed tests for the real transaction boundaries: active-operation exclusion, managed database ownership, desired revision increment, `waiting_backup`, no-backup immediate River insertion, audit metadata, and a failed backup reservation restoring the prior healthy desired state before agent contact.

- [ ] **Step 3: Run focused tests and verify the missing methods**

Run:

```bash
go test ./internal/control/wordpress -run 'Test(Uninstall|ReserveUninstall|ReinstallRemoved)' -count=1
```

Expected: FAIL because `Manager.Uninstall` and `ReserveUninstall` do not exist.

- [ ] **Step 4: Add exact manager/store interfaces**

Extend `ManagerStore`:

```go
ReserveUninstall(context.Context, auth.SessionUser, SiteIdentity, UninstallInput) (Instance, Operation, error)
FailUninstallReservation(context.Context, int64, int64, error) error
```

Add the manager method:

```go
func (m *Manager) Uninstall(ctx context.Context, actor auth.SessionUser, siteID int64, input UninstallInput) (Operation, error) {
    identity, err := m.authorize(ctx, actor, siteID)
    if err != nil {
        return Operation{}, err
    }
    input, err = normalizeUninstall(identity.Domain, input)
    if err != nil {
        return Operation{}, err
    }
    instance, operation, err := m.store.ReserveUninstall(ctx, actor, identity, input)
    if err != nil {
        return Operation{}, err
    }
    if !input.CreateBackup {
        return operation, nil
    }
    backupID, err := m.provisioner.CreateBackupForSubscription(ctx, actor, identity.SubscriptionID, types.CreateBackupReq{
        SubscriptionID: identity.SubscriptionID,
        Domain: identity.Domain,
        Username: identity.Username,
    })
    if err != nil {
        _ = m.store.FailUninstallReservation(ctx, instance.ID, operation.ID, err)
        return operation, err
    }
    if err = m.store.AttachBackupAndEnqueue(ctx, operation.ID, backupID); err != nil {
        _ = m.store.FailUninstallReservation(ctx, instance.ID, operation.ID, err)
        return operation, err
    }
    operation.BackupID, operation.Status = backupID, "waiting_backup"
    return operation, nil
}
```

`normalizeUninstall` must trim outer whitespace, require the canonical stored lower-case domain exactly, reject schemes/ports/paths, reject `DeleteDatabase && !CreateBackup`, and never accept a submitted database identity.

- [ ] **Step 5: Implement provider cleanup locking and the reservation transaction**

Add a dedicated removal lock path rather than weakening `lockAndValidateSite`. It must require active lifecycle for clients, permit authorized admins/owning resellers to clean suspended downstream sites, and omit the Toolkit entitlement check. In the transaction:

- Lock subscription and site advisory key.
- Lock the exact instance and linked database row.
- Reject active operations.
- Reject database deletion unless `database_managed=true` and the database matches site/subscription.
- Increment desired revision and set desired `absent`, observed `removing`, convergence `pending`.
- Insert `uninstall` with explicit backup/database booleans.
- Insert the River job only when backup is not requested.
- Audit `wordpress.uninstall.requested` with site ID and booleans only.

- [ ] **Step 6: Make reinstall reuse a removed tombstone**

Split the current failed-reservation display rule from install eligibility:

```go
func hiddenFailedReservation(instance Instance) bool {
    return instance.DatabaseID == 0 && instance.InstalledVersion == "" &&
        instance.ObservedState == "failed" && instance.ConvergenceStatus == "failed"
}

func reusableForInstall(instance Instance) bool {
    return hiddenFailedReservation(instance) || instance.ObservedState == "removed"
}
```

`Workspace` hides only `hiddenFailedReservation`; it must return a removed tombstone and its operation history to the UI. `ReserveInstall` accepts either reusable state, resets the instance to `present/pending`, clears live removal state, sets `database_managed=false`, increments the revision, and retains old operations. `CompleteInstallReservation` sets the new `database_id` and `database_managed=true` only after the Toolkit database intent is successfully attached. The old preserved database remains an ordinary site database and is never silently reused.

- [ ] **Step 7: Run manager/store tests and commit**

```bash
go test ./internal/control/wordpress -count=1
go test -race ./internal/control/wordpress -count=1
git diff --check
git add internal/control/wordpress/models.go internal/control/wordpress/manager.go internal/control/wordpress/store.go internal/control/wordpress/manager_test.go internal/control/wordpress/store_test.go
git commit -m "feat: reserve recoverable WordPress uninstalls"
```

---

### Task 5: River Execution, Completion, Cleanup, And Recovery

**Files:**
- Modify: `internal/control/wordpress/args.go`
- Modify: `internal/control/wordpress/args_test.go`
- Modify: `internal/control/wordpress/workers.go`
- Modify: `internal/control/wordpress/workers_test.go`
- Modify: `cmd/panel/main.go`

**Interfaces:**
- Consumes: reserved uninstall operations, durable backup manifests, `Agent.RunWordPress`, revision fencing, notification helpers, and Phase 33 tombstone states.
- Produces: uninstall-aware loading/validation, transactional completion, `CleanupRemovalArgs`, `CleanupRemovalWorker`, and removal reconciliation through the existing sweep.

- [ ] **Step 1: Write failing worker dependency and secrecy tests**

Cover same-site backup validation, missing database manifest, failed/deleted backup, disabled entitlement cleanup, stale revision no-op, request secrecy, agent failure, agent success plus SQL commit retry, and final tombstone state:

```go
func TestUninstallWorkerRequiresManagedDatabaseInBackupManifest(t *testing.T) {
    store := newWorkerStore(t, uninstallFixture{
        DeleteDatabase: true,
        BackupStatus: "active",
        BackupDatabases: []string{"other_database"},
        DatabaseName: "wp_s7_deadbeef",
    })
    agent := &recordingWordPressAgent{}
    err := NewOperationWorker(store, agent).Work(context.Background(), uninstallJob(store))
    if err == nil || agent.calls != 0 {
        t.Fatalf("unsafe uninstall reached agent: err=%v calls=%d", err, agent.calls)
    }
}
```

Serialize `OperationArgs` and the agent request and assert that admin passwords, database passwords, absolute home paths, and backup archive paths are absent.

- [ ] **Step 2: Write failing cleanup and reconciliation tests**

Add `TestCleanupRemovalWorkerFinalizesMatchingMarker`, `TestCleanupRemovalWorkerIgnoresStaleRevision`, `TestSweepRequeuesInterruptedRemoval`, and `TestRemovalCompletionCommitRetryIsIdempotent`.

- [ ] **Step 3: Run focused worker tests and verify failures**

```bash
go test ./internal/control/wordpress -run 'Test(UninstallWorker|CleanupRemoval|SweepRequeues|RemovalCompletion)' -count=1
```

Expected: FAIL because uninstall loading, completion, and cleanup jobs are absent.

- [ ] **Step 4: Extend loaded operation data and validation**

Load these fields in the existing read-only worker transaction:

```go
type loadedOperation struct {
    // existing fields
    databaseManaged                      bool
    backupArchive, backupChecksum        string
    backupSize                           int64
    backupSiteID, backupSubscriptionID   int64
    backupDatabases                      []string
}
```

For uninstall, skip the current entitlement and active-subscription checks but retain Classic hosting identity and the provider-authorized reservation. Require an active, complete, same-site backup when `BackupRequested` is true. Require the linked database in `backupDatabases` when deletion is requested. For all other actions preserve the Phase 32 validation unchanged.

- [ ] **Step 5: Build the typed uninstall agent request**

Extend `operationRequest` only for uninstall:

```go
if loaded.operation.Kind == types.WordPressActionUninstall {
    req.Removal = &types.WordPressRemovalSpec{
        DeleteDatabase: loaded.operation.DatabaseRemovalRequested,
        DatabaseName:   loaded.databaseName,
        DatabaseUser:   loaded.databaseUser,
    }
}
```

Leave `Credentials=nil`. After the agent returns, set `result.Removal.BackupID` from the control-plane operation before persistence.

- [ ] **Step 6: Implement transactional removal completion**

Branch from `completeOperation` into `completeUninstallOperation`. In one transaction:

- Lock the instance and verify desired revision and running operation.
- Require a non-nil removal result with files removed.
- If deletion was requested, require database removed and delete the exact linked database intent after clearing `wordpress_instances.database_id`.
- If deletion was not requested, clear the instance link but preserve the database row.
- Clear live identity/inventory/security/checksum/maintenance fields.
- Set observed `removed`, applied revision, and convergence `in_sync`.
- Retire the retry-only admin secret.
- Mark the operation succeeded with the bounded result.
- Resolve active WordPress security/update/failure notifications.
- Audit `wordpress.uninstall.completed`.
- Insert `CleanupRemovalArgs` in the same transaction.

- [ ] **Step 7: Add identifier-only cleanup and sweep recovery**

Define:

```go
type CleanupRemovalArgs struct {
    InstanceID      int64 `json:"instance_id" river:"unique"`
    OperationID     int64 `json:"operation_id" river:"unique"`
    DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (CleanupRemovalArgs) Kind() string { return "cleanup_wordpress_removal" }
func (CleanupRemovalArgs) InsertOpts() river.InsertOpts {
    return river.InsertOpts{Queue: "heavy", MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}
```

`CleanupRemovalWorker` reloads the removed tombstone and site identity, sends `WordPressActionUninstall` with `Removal.Finalize=true`, and treats an absent matching marker as success. Register it in `cmd/panel/main.go`.

Extend the sweep to requeue only an interrupted uninstall selected by this ownership-safe condition:

```sql
SELECT instance.id,operation.id,instance.desired_revision
FROM wordpress_instances instance
JOIN LATERAL (
    SELECT id,desired_revision,status FROM wordpress_operations
    WHERE instance_id=instance.id AND kind='uninstall'
    ORDER BY id DESC LIMIT 1
) operation ON operation.desired_revision=instance.desired_revision
WHERE instance.desired_state='absent'
  AND instance.observed_state IN ('removing','failed')
  AND operation.status IN ('pending','waiting_backup','running')
  AND NOT EXISTS (
      SELECT 1 FROM river_job
      WHERE kind='wordpress_operation'
        AND state IN ('available','pending','retryable','running','scheduled')
        AND args->>'instance_id'=instance.id::text
        AND args->>'desired_revision'=instance.desired_revision::text
  )
FOR UPDATE OF instance SKIP LOCKED
```

Never synthesize a new destructive choice, revive a terminal failed operation, or reuse an unrelated backup. Terminal failures require an explicit user retry that creates a new operation and desired revision.

- [ ] **Step 8: Run worker, panel, race, and secrecy tests**

```bash
go test ./internal/control/wordpress ./cmd/panel -count=1
go test -race ./internal/control/wordpress -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit River convergence**

```bash
git add internal/control/wordpress/args.go internal/control/wordpress/args_test.go internal/control/wordpress/workers.go internal/control/wordpress/workers_test.go cmd/panel/main.go
git commit -m "feat: converge WordPress uninstall operations"
```

---

### Task 6: HTTP Route And WordPress Workspace UX

**Files:**
- Modify: `internal/control/http/server.go`
- Modify: `internal/control/http/wordpress.go`
- Modify: `internal/control/http/wordpress_http_test.go`
- Modify: `internal/control/web/workspace.templ`
- Modify: `internal/control/web/wordpress_render_test.go`
- Modify: `internal/control/web/static/app.js`
- Modify: `internal/control/web/assets/input.css`
- Generate: `internal/control/web/workspace_templ.go`
- Generate: `internal/control/web/static/app.css`

**Interfaces:**
- Consumes: `Manager.Uninstall`, WordPress workspace tombstone/operation fields, support-view redirect helpers, CSRF, modal behavior, and notice rendering.
- Produces: `POST /sites/{id}/wordpress/uninstall`, enhanced `202` responses, distinct Detach/Uninstall UX, progress states, and reinstall presentation.

- [ ] **Step 1: Write failing handler tests**

Extend the WordPress service fake with:

```go
Uninstall(context.Context, auth.SessionUser, int64, controlwordpress.UninstallInput) (controlwordpress.Operation, error)
```

Add tests for CSRF, exact confirmation, successful HTML redirect, enhanced JSON `202`, `404` ownership behavior, suspended client conflict, support prefix preservation, and no sensitive output:

```go
func TestWordPressUninstallEnhancedResponseIsQueuedAndSecretFree(t *testing.T) {
    // POST create_backup=on, delete_database=on, confirm_domain=owned.test
    // Expect 202 and only ok, operation_id, status, and backup_id.
    // Assert the body omits db_name, db_user, archive_path, password, and /home/.
}
```

- [ ] **Step 2: Write failing render and interaction tests**

Assert installed pages contain both `Detach from Toolkit` and `Uninstall WordPress`, the dialog defaults backup on, database deletion is available only for managed databases, and the exact domain appears as the confirmation label. Assert removed pages show `WordPress removed`, backup/database disposition, and `Install WordPress again`. Assert pending pages disable incompatible controls.

- [ ] **Step 3: Run HTTP/web tests and confirm the route is missing**

```bash
go test ./internal/control/http ./internal/control/web -run 'WordPress.*(Uninstall|Removed|Danger)' -count=1
```

Expected: FAIL because the route and dialog are absent.

- [ ] **Step 4: Add the service interface, route, and handler**

Register:

```go
mux.HandleFunc("POST /sites/{id}/wordpress/uninstall", s.handleUninstallWordPress)
```

The handler uses `wordpressMutationRequest`, parses booleans with the existing form helper, passes only `UninstallInput`, and returns:

```go
map[string]any{
    "ok": true,
    "operation_id": operation.ID,
    "status": operation.Status,
    "backup_id": operation.BackupID,
}
```

Use `wordpress-uninstall-backup-pending` when status is `waiting_backup`; otherwise use `wordpress-uninstall-queued`. Map `ErrNotFound` to `404`, invalid confirmation to `400`, and busy/inactive states to `409` without raw error pages.

- [ ] **Step 5: Build the Danger Zone dialog and removed state**

Keep Detach unchanged. Add an Uninstall panel with consequence text and a modal form using the standard dialog component. The form posts the three allowlisted fields and uses the stored canonical domain. Use `data-np-wordpress-uninstall` to make the database checkbox follow the backup checkbox; the server remains authoritative.

For removed tombstones, render the recovery summary from the latest successful uninstall result and show the normal install dialog. Never render database names, archive paths, admin secrets, or quarantine details.

- [ ] **Step 6: Add accessible interaction behavior and responsive styles**

In `app.js`, scope the checkbox dependency to the open uninstall form:

```js
document.querySelectorAll("[data-np-wordpress-uninstall]").forEach((form) => {
  const backup = form.querySelector('[name="create_backup"]');
  const database = form.querySelector('[name="delete_database"]');
  if (!backup || !database) return;
  const sync = () => {
    database.disabled = !backup.checked;
    if (!backup.checked) database.checked = false;
  };
  backup.addEventListener("change", sync);
  sync();
});
```

Use existing modal focus trapping, Escape handling, and restoration. Add only targeted CSS for the removal summary and warning copy; preserve the domain shell typography and 44px mobile controls.

- [ ] **Step 7: Generate assets, run tests, and commit**

```bash
task templ:generate
task tailwind:build
go test ./internal/control/http ./internal/control/web -count=1
git diff --check
git add internal/control/http/server.go internal/control/http/wordpress.go internal/control/http/wordpress_http_test.go internal/control/web/workspace.templ internal/control/web/workspace_templ.go internal/control/web/wordpress_render_test.go internal/control/web/static/app.js internal/control/web/assets/input.css internal/control/web/static/app.css
git commit -m "feat: add WordPress uninstall workspace"
```

---

### Task 7: Documentation And Ubuntu 24.04 Acceptance

**Files:**
- Create: `deploy/multipass/phase33-verify.sh`
- Create: `deploy/multipass/phase33_verify_test.go`
- Modify: `deploy/multipass/deployment-verify.sh`
- Modify: `deploy/multipass/single_vm_verify_test.go`
- Modify: `README.md`
- Modify: `IMPLEMENTATION_PLAN.md`
- Modify: `docs/RECOVERY.md`

**Interfaces:**
- Consumes: live Phase 32 verifier, Phase 33 HTTP workflow, PostgreSQL states, MariaDB state, backup archives, WordPress allocation, and single-VM helper functions.
- Produces: a repeatable live uninstall/reinstall/recovery acceptance gate and operator documentation.

- [ ] **Step 1: Write the failing verifier contract test**

Require these contracts in `phase33_verify_test.go`:

```go
func TestPhase33VerifierCoversSafeWordPressUninstall(t *testing.T) {
    script := readExecutableScript(t, "phase33-verify.sh")
    requireScriptContracts(t, script, map[string][]string{
        "chain": {"phase32-verify.sh", "NAKPANEL_SKIP_PRIOR_PHASES", "sync_repo", "vm_ip"},
        "backup_gate": {"wordpress/uninstall", "create_backup=on", "delete_database=on", "waiting_backup", "checksum_sha256", "database_names"},
        "removal": {"observed_state", "removed", "wp core is-installed", "information_schema", "mysql.user"},
        "preservation": {"curl", "Nakpanel", "tls_status", "dns_zones", "subscription_id"},
        "reinstall": {"wordpress/install", "wp core verify-checksums", "desired_revision"},
        "external_database": {"action=discover", "database_managed", "database preserved"},
        "rollback": {"database-removal failure", "original site remains available"},
    })
}
```

Forbid direct inserts/updates to WordPress tables and direct deletion of the test database before the product request.

- [ ] **Step 2: Run the verifier tests and confirm Phase 33 is missing**

```bash
go test ./deploy/multipass -run Phase33 -count=1
```

Expected: FAIL because the Phase 33 verifier is absent.

- [ ] **Step 3: Implement the bounded Phase 33 verifier**

The script must:

- Source `common.sh`, use `nakpanel-lab`, and run Phase 32 unless skipped.
- Reinstall current binaries and migrations.
- Create a fresh Classic PHP site and Toolkit-managed WordPress installation through panel routes.
- Add a post and media upload, then request uninstall with backup and database deletion.
- Poll boundedly for backup `active` and uninstall `removed/in_sync`.
- Verify the backup has nonzero size/checksum and contains the managed database in `database_names`.
- Verify WordPress files and MariaDB database/principal are absent.
- Verify the domain still serves the generated placeholder and its site, TLS, DNS, and subscription rows remain.
- Verify WordPress usage allocation decreased only after removal.
- Reinstall through the panel and run `wp core verify-checksums`.
- Discover a separately prepared WordPress installation and prove its database is preserved after uninstall.
- Exercise a deterministic pre-drop failure without test-only production hooks: wait for the recovery backup to become active, stop the panel before the snoozed uninstall retry, stop MariaDB, restart the panel so the agent removal fails before a database mutation, restart MariaDB, and prove the original WordPress files and site are restored and available.
- Scan River args, audit metadata, journal output, HTML, and JSON for passwords, `/home/`, archive paths, and quarantine paths.
- Use `mktemp -d`, cleanup traps, bounded polling, and explicit success marker.

- [ ] **Step 4: Make Phase 33 the final deployment gate**

Update `deployment-verify.sh` to invoke `phase33-verify.sh`. Update single-VM static tests so Phase 33 is final and Phase 32 remains directly runnable for diagnosis.

- [ ] **Step 5: Document operator behavior and recovery**

README must distinguish Detach from Uninstall. `docs/RECOVERY.md` must document the `waiting_backup`, `removing`, `removed`, and failed convergence states, recovery backup lookup, safe retry, preserved external database, quarantine ownership, and the prohibition against manually deleting markers. `IMPLEMENTATION_PLAN.md` must record Phase 33 as implemented only after the live verifier passes.

- [ ] **Step 6: Run static verifier tests and commit**

```bash
chmod +x deploy/multipass/phase33-verify.sh
go test ./deploy/multipass -count=1
find deploy -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
git diff --check
git add deploy/multipass/phase33-verify.sh deploy/multipass/phase33_verify_test.go deploy/multipass/deployment-verify.sh deploy/multipass/single_vm_verify_test.go README.md IMPLEMENTATION_PLAN.md docs/RECOVERY.md
git commit -m "test: verify safe WordPress uninstall on Ubuntu"
```

---

### Task 8: Complete Regression, Browser, And Live Verification

**Files:**
- Modify only files required by failures found during this task.

**Interfaces:**
- Consumes: all Phase 33 implementation tasks.
- Produces: evidence that the exact branch passes static, race, browser, and Ubuntu 24.04 acceptance without regressions.

- [ ] **Step 1: Regenerate committed artifacts from the final source**

```bash
task sqlc:generate
task templ:generate
task tailwind:build
```

Expected: generation completes without missing dependencies.

- [ ] **Step 2: Run the full Go and race suites**

```bash
go test ./... -count=1
go test -race ./internal/control/wordpress ./internal/agent/ops ./internal/control/http -count=1
go vet ./...
```

Expected: PASS with no races or vet findings.

- [ ] **Step 3: Build and validate repository hygiene**

```bash
task build
git diff --check
find deploy -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
```

Expected: all binaries build and all scripts parse.

- [ ] **Step 4: Run desktop and mobile browser QA**

At `1440x1000` and `390x844`, verify:

- Detach and Uninstall are visually distinct.
- The uninstall dialog opens, traps focus, closes with Escape, and restores focus.
- Clearing backup disables and clears database deletion.
- Exact-domain confirmation controls submission.
- Pending, failed, removed, and reinstall states are legible.
- No horizontal document overflow, clipped text, overlapping controls, or console errors occur.
- Sensitive names, paths, credentials, and quarantine details are absent from DOM and JSON.

- [ ] **Step 5: Run the fresh single-VM deployment verifier**

```bash
deploy/multipass/deployment-verify.sh
```

Expected: Phase 33 finishes successfully on Ubuntu 24.04 and `multipass list` shows only `nakpanel-lab` among Nakpanel deployment VMs.

- [ ] **Step 6: Review the final diff for scope and security**

```bash
git status --short
git diff --stat HEAD~7..HEAD
git log --oneline -8
```

Confirm no unrelated refactor, generated junk, local secret, VM artifact, database credential, archive path, or quarantine path was committed.

When Step 2-5 exposes a defect, return to the task that owns the failing component, add a regression test there, apply the correction within that task's declared file set, rerun its focused commands, and repeat Task 8 from Step 1. Do not create an empty verification commit when no correction was required.
