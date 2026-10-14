-- +goose Up
ALTER TABLE subscriptions ADD COLUMN primary_site_id BIGINT;
ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_primary_site_scope_fk
    FOREIGN KEY (primary_site_id,id) REFERENCES sites(id,subscription_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE sites ADD COLUMN removal_state TEXT NOT NULL DEFAULT 'none'
    CHECK (removal_state IN ('none','queued','removing','failed'));
ALTER TABLE sites ADD COLUMN removal_revision BIGINT NOT NULL DEFAULT 0 CHECK (removal_revision>=0);

UPDATE subscriptions sub SET primary_site_id=COALESCE(
    (SELECT site.id FROM billing_accounts billing JOIN sites site ON site.id=billing.primary_site_id
     WHERE billing.subscription_id=sub.id AND site.subscription_id=sub.id AND site.parent_site_id IS NULL LIMIT 1),
    (SELECT site.id FROM sites site WHERE site.subscription_id=sub.id AND site.parent_site_id IS NULL
     ORDER BY site.created_at,site.id LIMIT 1)
);

CREATE TABLE site_removal_operations (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE CHECK (request_id ~ '^[a-f0-9]{32}$'),
    site_id BIGINT NOT NULL,
    subscription_id BIGINT NOT NULL,
    customer_id BIGINT NOT NULL,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_label TEXT NOT NULL,
    domain TEXT NOT NULL,
    parent_site_id BIGINT,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    preview_digest TEXT NOT NULL,
    delete_database_ids BIGINT[] NOT NULL DEFAULT '{}',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','waiting','running','failed','completed')),
    stage TEXT NOT NULL DEFAULT 'waiting' CHECK (stage IN ('waiting','stop_services','remove_hosting','reconcile_shared','finalize','completed')),
    checkpoints TEXT[] NOT NULL DEFAULT '{}',
    last_error TEXT NOT NULL DEFAULT '' CHECK (octet_length(last_error)<=512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX site_removal_active_site_idx ON site_removal_operations(site_id) WHERE state<>'completed';
CREATE INDEX site_removal_subscription_idx ON site_removal_operations(subscription_id,state);
CREATE TABLE site_removal_targets (
    operation_id BIGINT NOT NULL REFERENCES site_removal_operations(id) ON DELETE CASCADE,
    site_id BIGINT NOT NULL,
    released BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY(operation_id,site_id)
);
CREATE UNIQUE INDEX site_removal_target_reserved_idx ON site_removal_targets(site_id) WHERE NOT released;

-- +goose StatementBegin
CREATE FUNCTION nakpanel_protect_removal_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.request_id,NEW.site_id,NEW.subscription_id,NEW.customer_id,NEW.actor_label,NEW.domain,NEW.parent_site_id,
        NEW.snapshot,NEW.preview_digest,NEW.delete_database_ids)
       IS DISTINCT FROM
       (OLD.request_id,OLD.site_id,OLD.subscription_id,OLD.customer_id,OLD.actor_label,OLD.domain,OLD.parent_site_id,
        OLD.snapshot,OLD.preview_digest,OLD.delete_database_ids) THEN
        RAISE EXCEPTION 'approved website removal scope is immutable';
    END IF;
    IF NEW.revision<OLD.revision OR (OLD.state='completed' AND NEW.state<>'completed') THEN
        RAISE EXCEPTION 'website removal cannot regress';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER removal_approval_guard BEFORE UPDATE ON site_removal_operations FOR EACH ROW EXECUTE FUNCTION nakpanel_protect_removal_approval();

CREATE FUNCTION nakpanel_removal_site_ids(table_value TEXT,row_value JSONB) RETURNS BIGINT[]
LANGUAGE plpgsql AS $$
DECLARE ids BIGINT[] := '{}'; value BIGINT;
BEGIN
    IF table_value='sites' THEN
        ids:=ARRAY[NULLIF(row_value->>'id','')::BIGINT,NULLIF(row_value->>'parent_site_id','')::BIGINT];
    ELSIF table_value='staging_operations' THEN
        ids:=ARRAY[NULLIF(row_value->>'source_site_id','')::BIGINT,NULLIF(row_value->>'target_site_id','')::BIGINT];
    ELSIF table_value='dns_records' THEN
        SELECT site_id INTO value FROM dns_zones WHERE id=NULLIF(row_value->>'zone_id','')::BIGINT;
        ids:=ARRAY[value,NULLIF(row_value->>'owner_site_id','')::BIGINT];
        ids:=ids||ARRAY(SELECT candidate.id FROM sites candidate JOIN dns_zones zone ON zone.id=NULLIF(row_value->>'zone_id','')::BIGINT
            JOIN sites zone_site ON zone_site.id=zone.site_id
            WHERE candidate.subscription_id=zone_site.subscription_id AND candidate.domain=CASE
              WHEN row_value->>'host'='@' THEN zone.domain
              WHEN lower(rtrim(row_value->>'host','.')) LIKE '%.'||zone.domain THEN lower(rtrim(row_value->>'host','.'))
              ELSE lower(rtrim(row_value->>'host','.'))||'.'||zone.domain END);
    ELSIF table_value IN ('mailboxes','mail_aliases') THEN
        SELECT site.id INTO value FROM mail_domains md JOIN sites site ON site.domain=md.domain AND site.subscription_id=md.subscription_id
        WHERE md.id=NULLIF(row_value->>'mail_domain_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='mail_domains' THEN
        SELECT id INTO value FROM sites WHERE domain=row_value->>'domain' AND subscription_id=NULLIF(row_value->>'subscription_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='restore_runs' THEN
        SELECT site_id INTO value FROM backups WHERE id=NULLIF(row_value->>'backup_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='sftp_access_identities' THEN
        ids:=ARRAY(SELECT id FROM sites WHERE subscription_id=NULLIF(row_value->>'subscription_id','')::BIGINT
          AND row_value->>'relative_root' LIKE 'domains/%'
          AND domain=split_part(row_value->>'relative_root','/',2));
    ELSIF table_value IN ('php_deployments','php_environment_bindings','php_workers') THEN
        SELECT site_id INTO value FROM php_applications WHERE id=NULLIF(row_value->>'application_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='wordpress_operations' THEN
        SELECT site_id INTO value FROM wordpress_instances WHERE id=NULLIF(row_value->>'instance_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value IN ('application_ports','application_volumes','application_generations','application_secret_bindings') THEN
        SELECT site_id INTO value FROM application_instances WHERE id=NULLIF(row_value->>'application_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='git_deployments' THEN
        SELECT site_id INTO value FROM git_repositories WHERE id=NULLIF(row_value->>'repository_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSIF table_value='scheduled_task_runs' THEN
        SELECT site_id INTO value FROM scheduled_tasks WHERE id=NULLIF(row_value->>'task_id','')::BIGINT;
        ids:=ARRAY[value];
    ELSE
        ids:=ARRAY[NULLIF(row_value->>'site_id','')::BIGINT];
    END IF;
    RETURN array_remove(ids,NULL);
END;
$$;

CREATE FUNCTION nakpanel_guard_site_removal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ids BIGINT[] := '{}'; site_value BIGINT; sub_value BIGINT; state_value TEXT;
BEGIN
    IF current_setting('nakpanel.account_teardown',true)='on' THEN
        IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    IF TG_OP<>'INSERT' THEN ids:=ids||nakpanel_removal_site_ids(TG_TABLE_NAME,to_jsonb(OLD)); END IF;
    IF TG_OP<>'DELETE' THEN ids:=ids||nakpanel_removal_site_ids(TG_TABLE_NAME,to_jsonb(NEW)); END IF;
    FOR sub_value IN SELECT DISTINCT subscription_id FROM sites WHERE id=ANY(ids) ORDER BY subscription_id LOOP
        PERFORM nakpanel_assert_account_mutable(sub_value);
    END LOOP;
    -- Resolve again after subscription locks: a concurrent child may have appeared.
    ids:='{}';
    IF TG_OP<>'INSERT' THEN ids:=ids||nakpanel_removal_site_ids(TG_TABLE_NAME,to_jsonb(OLD)); END IF;
    IF TG_OP<>'DELETE' THEN ids:=ids||nakpanel_removal_site_ids(TG_TABLE_NAME,to_jsonb(NEW)); END IF;
    IF TG_TABLE_NAME='staging_operations' AND TG_OP='DELETE' THEN
      IF EXISTS(
        SELECT 1 FROM site_removal_operations operation
        WHERE operation.id::TEXT=current_setting('nakpanel.site_removal_operation',true) AND operation.state<>'completed'
          AND operation.snapshot->'resources' @> jsonb_build_array(jsonb_build_object(
            'kind','staging','id',OLD.id,'site_id',OLD.source_site_id,'parent_id',OLD.target_site_id))
          AND (operation.snapshot->'sites' @> jsonb_build_array(jsonb_build_object('site_id',OLD.source_site_id))
            OR operation.snapshot->'sites' @> jsonb_build_array(jsonb_build_object('site_id',OLD.target_site_id)))
      ) THEN RETURN OLD; END IF;
    END IF;
    FOR site_value IN SELECT DISTINCT id FROM sites WHERE id=ANY(ids) ORDER BY id LOOP
        SELECT removal_state INTO state_value FROM sites WHERE id=site_value FOR SHARE;
        IF state_value<>'none' AND NOT EXISTS(
            SELECT 1 FROM site_removal_operations operation
            WHERE operation.id::TEXT=current_setting('nakpanel.site_removal_operation',true)
              AND operation.state<>'completed'
              AND operation.snapshot->'sites' @> jsonb_build_array(jsonb_build_object('site_id',site_value))
        ) THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='website removal has started';
        END IF;
    END LOOP;
    IF TG_TABLE_NAME='sites' THEN
        IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM subscriptions WHERE primary_site_id=OLD.id) THEN
            RAISE EXCEPTION 'primary website cannot be individually removed';
        END IF;
        IF TG_OP='UPDATE' AND NEW.parent_site_id IS NOT NULL AND EXISTS(SELECT 1 FROM subscriptions WHERE primary_site_id=OLD.id) THEN
            RAISE EXCEPTION 'primary website cannot become a subdomain';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

CREATE FUNCTION nakpanel_guard_removal_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE sub_value BIGINT;
BEGIN
    IF TG_TABLE_NAME='subscriptions' THEN
        IF NEW.primary_site_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM sites WHERE id=NEW.primary_site_id AND subscription_id=NEW.id AND parent_site_id IS NULL
        ) THEN RAISE EXCEPTION 'primary website must be a root in this subscription'; END IF;
        IF NEW.customer_id IS NOT DISTINCT FROM OLD.customer_id THEN RETURN NEW; END IF;
        sub_value:=OLD.id;
    ELSIF TG_TABLE_NAME='customers' THEN
        IF NEW.reseller_id IS NOT DISTINCT FROM OLD.reseller_id THEN RETURN NEW; END IF;
    ELSIF TG_TABLE_NAME='billing_accounts' THEN
        IF NEW.provisioning_state NOT IN ('terminating','terminated') OR NEW.provisioning_state=OLD.provisioning_state THEN RETURN NEW; END IF;
        sub_value:=OLD.subscription_id;
    END IF;
    IF TG_TABLE_NAME='customers' THEN
        FOR sub_value IN SELECT id FROM subscriptions WHERE customer_id=OLD.id ORDER BY id LOOP
            PERFORM nakpanel_assert_account_mutable(sub_value);
            IF EXISTS(SELECT 1 FROM site_removal_operations WHERE subscription_id=sub_value AND state<>'completed') THEN
                RAISE EXCEPTION 'finish or retry website removal before changing ownership';
            END IF;
        END LOOP;
    ELSE
        PERFORM nakpanel_assert_account_mutable(sub_value);
        IF EXISTS(SELECT 1 FROM site_removal_operations WHERE subscription_id=sub_value AND state<>'completed') THEN
            RAISE EXCEPTION 'finish or retry website removal before account changes';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION nakpanel_assert_service_hostname(host_value TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE sub_value BIGINT;
BEGIN
    FOR sub_value IN SELECT DISTINCT subscription_id FROM sites
       WHERE lower(rtrim(host_value,'.'))=domain OR lower(rtrim(host_value,'.')) LIKE '%.'||domain ORDER BY subscription_id LOOP
       PERFORM nakpanel_assert_account_mutable(sub_value);
    END LOOP;
    IF EXISTS(SELECT 1 FROM sites WHERE removal_state<>'none'
      AND (lower(rtrim(host_value,'.'))=domain OR lower(rtrim(host_value,'.')) LIKE '%.'||domain)) THEN
       RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='server service cannot depend on a removing website';
    END IF;
END;
$$;
CREATE FUNCTION nakpanel_guard_removal_dependency() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE host_value TEXT;
BEGIN
    IF TG_TABLE_NAME='mail_settings' THEN
      PERFORM nakpanel_assert_service_hostname(NEW.mail_hostname);
    ELSE
      FOR host_value IN SELECT primary_nameserver FROM dns_template_revisions WHERE id=NEW.active_revision_id
        UNION SELECT value_template FROM dns_template_records WHERE revision_id=NEW.active_revision_id AND record_type='NS'
          AND value_template NOT LIKE '%$%' AND value_template NOT LIKE '%<%' LOOP
        PERFORM nakpanel_assert_service_hostname(host_value);
      END LOOP;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER removal_mail_dependency_guard BEFORE INSERT OR UPDATE ON mail_settings FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_removal_dependency();
CREATE TRIGGER removal_dns_dependency_guard BEFORE INSERT OR UPDATE ON dns_template_state FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_removal_dependency();

DO $$
DECLARE table_value TEXT;
BEGIN
    FOREACH table_value IN ARRAY ARRAY['sites','databases','backups','restore_runs','webmail_hosts','dns_zones','dns_records','sftp_access_identities',
        'ftp_accounts','scheduled_tasks','scheduled_task_runs','mail_domains','mailboxes','mail_aliases','application_instances',
        'application_ports','application_volumes','application_generations','application_secret_bindings','protected_directories',
        'git_repositories','git_deployments','staging_operations','site_runtime_generations','site_policy_overrides',
        'php_applications','php_deployments','php_environment_bindings','php_workers','wordpress_instances','wordpress_operations',
        'site_web_statistics']
    LOOP
        EXECUTE format('CREATE TRIGGER site_removal_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_site_removal()',table_value);
    END LOOP;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER removal_subscription_owner_guard BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_removal_owner();
CREATE TRIGGER removal_customer_owner_guard BEFORE UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_removal_owner();
CREATE TRIGGER removal_billing_owner_guard BEFORE UPDATE ON billing_accounts FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_removal_owner();
-- +goose StatementBegin
CREATE FUNCTION nakpanel_claim_primary_site() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.parent_site_id IS NULL THEN
        UPDATE subscriptions SET primary_site_id=NEW.id WHERE id=NEW.subscription_id AND primary_site_id IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER removal_primary_claim AFTER INSERT ON sites FOR EACH ROW EXECUTE FUNCTION nakpanel_claim_primary_site();

CREATE OR REPLACE VIEW stalwart_accounts AS
SELECT lower(mb.local_part)||'@'||md.domain AS name,'individual' AS type,mb.password_hash AS secret,'' AS description,
CASE WHEN mb.quota_mb<=0 THEN 0 ELSE mb.quota_mb::bigint*1048576 END AS quota
FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id
WHERE mb.enabled AND md.effective_enabled AND NOT md.delete_requested
AND NOT EXISTS(SELECT 1 FROM sites s WHERE s.subscription_id=md.subscription_id AND s.domain=md.domain AND s.removal_state<>'none');
CREATE OR REPLACE VIEW stalwart_domains AS SELECT domain AS name FROM mail_domains md
WHERE effective_enabled AND NOT delete_requested
AND NOT EXISTS(SELECT 1 FROM sites s WHERE s.subscription_id=md.subscription_id AND s.domain=md.domain AND s.removal_state<>'none');
CREATE OR REPLACE VIEW stalwart_emails AS
SELECT account.name AS name,account.name AS address,'primary' AS type FROM stalwart_accounts account
UNION ALL
SELECT lower(dest.addr) AS name,lower(al.local_part)||'@'||md.domain AS address,'alias' AS type
FROM mail_aliases al JOIN mail_domains md ON md.id=al.mail_domain_id AND md.effective_enabled AND NOT md.delete_requested
CROSS JOIN LATERAL unnest(al.destinations) AS dest(addr)
WHERE EXISTS(SELECT 1 FROM stalwart_accounts account WHERE account.name=lower(dest.addr))
AND NOT EXISTS(SELECT 1 FROM sites s WHERE s.subscription_id=md.subscription_id AND s.domain=md.domain AND s.removal_state<>'none');

-- +goose Down
CREATE OR REPLACE VIEW stalwart_accounts AS
SELECT lower(mb.local_part)||'@'||md.domain AS name,'individual' AS type,mb.password_hash AS secret,'' AS description,
CASE WHEN mb.quota_mb<=0 THEN 0 ELSE mb.quota_mb::bigint*1048576 END AS quota
FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id
WHERE mb.enabled AND md.effective_enabled AND NOT md.delete_requested;
CREATE OR REPLACE VIEW stalwart_domains AS SELECT domain AS name FROM mail_domains WHERE effective_enabled AND NOT delete_requested;
CREATE OR REPLACE VIEW stalwart_emails AS
SELECT account.name AS name,account.name AS address,'primary' AS type FROM stalwart_accounts account
UNION ALL
SELECT lower(dest.addr) AS name,lower(al.local_part)||'@'||md.domain AS address,'alias' AS type
FROM mail_aliases al JOIN mail_domains md ON md.id=al.mail_domain_id AND md.effective_enabled AND NOT md.delete_requested
CROSS JOIN LATERAL unnest(al.destinations) AS dest(addr)
WHERE EXISTS(SELECT 1 FROM stalwart_accounts account WHERE account.name=lower(dest.addr));
DROP TRIGGER removal_subscription_owner_guard ON subscriptions;
DROP TRIGGER removal_mail_dependency_guard ON mail_settings;
DROP TRIGGER removal_dns_dependency_guard ON dns_template_state;
DROP FUNCTION nakpanel_guard_removal_dependency();
DROP FUNCTION nakpanel_assert_service_hostname(TEXT);
DROP TRIGGER removal_customer_owner_guard ON customers;
DROP TRIGGER removal_billing_owner_guard ON billing_accounts;
DROP TRIGGER removal_primary_claim ON sites;
DROP FUNCTION nakpanel_claim_primary_site();
-- +goose StatementBegin
DO $$
DECLARE table_value TEXT;
BEGIN
    FOR table_value IN SELECT relname FROM pg_class relation JOIN pg_trigger trigger ON trigger.tgrelid=relation.oid
        JOIN pg_namespace ns ON ns.oid=relation.relnamespace
        WHERE trigger.tgname='site_removal_guard' AND ns.nspname=current_schema()
    LOOP EXECUTE format('DROP TRIGGER site_removal_guard ON %I',table_value); END LOOP;
END;
$$;
-- +goose StatementEnd
DROP FUNCTION nakpanel_guard_site_removal();
DROP FUNCTION nakpanel_removal_site_ids(TEXT,JSONB);
DROP FUNCTION nakpanel_guard_removal_owner();
DROP TABLE site_removal_targets;
DROP TABLE site_removal_operations;
DROP FUNCTION nakpanel_protect_removal_approval();
ALTER TABLE subscriptions DROP CONSTRAINT subscriptions_primary_site_scope_fk;
ALTER TABLE subscriptions DROP COLUMN primary_site_id;
ALTER TABLE sites DROP COLUMN removal_state,DROP COLUMN removal_revision;
