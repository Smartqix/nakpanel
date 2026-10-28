-- +goose Up
ALTER TABLE issues ADD COLUMN last_check_at TIMESTAMPTZ;
ALTER TABLE issues ADD COLUMN last_check_status TEXT NOT NULL DEFAULT 'unknown' CHECK(last_check_status IN ('unknown','checking','failed','verified'));
ALTER TABLE operation_attempts ADD COLUMN river_attempt INTEGER NOT NULL DEFAULT 1 CHECK(river_attempt>0);
ALTER TABLE operation_attempts DROP CONSTRAINT operation_attempts_river_job_id_key;
ALTER TABLE operation_attempts ADD CONSTRAINT operation_attempts_source_execution UNIQUE(river_job_id,river_attempt);

-- +goose StatementBegin
CREATE FUNCTION nakpanel_operation_arg_id(value jsonb,key text) RETURNS bigint LANGUAGE SQL IMMUTABLE AS $$
 SELECT CASE WHEN value->>key ~ '^[0-9]{1,18}$' THEN (value->>key)::bigint ELSE 0 END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION nakpanel_record_operation_job() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
 rk text := 'server'; rid bigint := 0; sub_id bigint := 0;
 op_id bigint; linked_id bigint; event_id bigint; incident_id bigint;
 op_state text; attempt_state text; label text; incident_kind text; incident_condition text;
 revision bigint := 0; subject_id bigint := 0;
BEGIN
 IF NEW.kind NOT IN ('create_site','create_database','issue_cert','install_custom_cert','create_backup','restore_backup','configure_webmail','configure_dns_zone','reconcile_system','configure_mail','set_hosting_state','deploy_php_release','rollback_php_release','wordpress_operation','run_scheduled_task','run_staging_operation','mail_import','system_apply_updates','system_control_service','server_backup') THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND OLD.state=NEW.state AND OLD.attempt=NEW.attempt THEN RETURN NEW; END IF;

 rid:=nakpanel_operation_arg_id(NEW.args,'site_id');
 IF rid=0 AND NEW.kind IN ('create_backup','restore_backup') THEN SELECT COALESCE(site_id,0),COALESCE(subscription_id,0) INTO rid,sub_id FROM backups WHERE id=nakpanel_operation_arg_id(NEW.args,'backup_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='configure_dns_zone' THEN SELECT site_id INTO rid FROM dns_zones WHERE id=nakpanel_operation_arg_id(NEW.args,'zone_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='configure_webmail' THEN SELECT site_id INTO rid FROM webmail_hosts WHERE id=nakpanel_operation_arg_id(NEW.args,'webmail_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind IN ('deploy_php_release','rollback_php_release') THEN SELECT site_id INTO rid FROM php_applications WHERE id=nakpanel_operation_arg_id(NEW.args,'application_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='wordpress_operation' THEN SELECT site_id INTO rid FROM wordpress_instances WHERE id=nakpanel_operation_arg_id(NEW.args,'instance_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='create_database' THEN SELECT COALESCE(site_id,0),COALESCE(subscription_id,0) INTO rid,sub_id FROM databases WHERE id=nakpanel_operation_arg_id(NEW.args,'database_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='run_scheduled_task' THEN SELECT COALESCE(t.site_id,0),t.subscription_id INTO rid,sub_id FROM scheduled_task_runs r JOIN scheduled_tasks t ON t.id=r.task_id WHERE r.id=nakpanel_operation_arg_id(NEW.args,'run_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='mail_import' THEN SELECT md.site_id,md.subscription_id INTO rid,sub_id FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE i.id=NEW.args->>'import_id'; END IF;
 IF COALESCE(rid,0)=0 AND NEW.kind='run_staging_operation' THEN SELECT target_site_id INTO rid FROM staging_operations WHERE id=nakpanel_operation_arg_id(NEW.args,'operation_id'); END IF;
 IF COALESCE(rid,0)=0 AND NEW.args->>'domain' IS NOT NULL THEN SELECT id INTO rid FROM sites WHERE domain=NEW.args->>'domain'; END IF;
 IF COALESCE(rid,0)>0 THEN rk:='site'; ELSE
  rid:=COALESCE(NULLIF(sub_id,0),NULLIF(nakpanel_operation_arg_id(NEW.args,'subscription_id'),0),0);
  IF rid>0 THEN rk:='subscription'; ELSE rk:='server'; END IF;
 END IF;
 revision:=nakpanel_operation_arg_id(NEW.args,'desired_revision');
 label:=CASE NEW.kind WHEN 'create_site' THEN 'Set up website' WHEN 'create_database' THEN 'Create database' WHEN 'issue_cert' THEN 'Issue certificate' WHEN 'install_custom_cert' THEN 'Install certificate' WHEN 'create_backup' THEN 'Create backup' WHEN 'restore_backup' THEN 'Restore backup' WHEN 'configure_webmail' THEN 'Configure webmail' WHEN 'configure_mail' THEN 'Apply mail settings' WHEN 'configure_dns_zone' THEN 'Apply DNS changes' WHEN 'reconcile_system' THEN 'Reconcile configuration' WHEN 'set_hosting_state' THEN 'Apply hosting state' WHEN 'deploy_php_release' THEN 'Deploy application' WHEN 'rollback_php_release' THEN 'Roll back application' WHEN 'wordpress_operation' THEN 'WordPress operation' WHEN 'run_scheduled_task' THEN 'Run scheduled task' WHEN 'mail_import' THEN 'Import mail' WHEN 'system_apply_updates' THEN 'Install system updates' WHEN 'server_backup' THEN 'Create server backup' WHEN 'system_control_service' THEN concat(CASE NEW.args->>'action' WHEN 'restart' THEN 'Restart' WHEN 'reload' THEN 'Reload' WHEN 'start' THEN 'Start' WHEN 'stop' THEN 'Stop' ELSE 'Manage' END,' ',CASE NEW.args->>'service_id' WHEN 'web' THEN 'nginx' WHEN 'dns' THEN 'BIND' WHEN 'mail' THEN 'Stalwart Mail' WHEN 'php-8.3' THEN 'PHP 8.3 FPM' WHEN 'php-8.4' THEN 'PHP 8.4 FPM' WHEN 'php-8.5' THEN 'PHP 8.5 FPM' ELSE 'service' END) ELSE 'Background operation' END;
 op_state:=CASE NEW.state::text WHEN 'running' THEN 'running' WHEN 'completed' THEN 'succeeded' WHEN 'discarded' THEN 'failed' WHEN 'cancelled' THEN 'cancelled' WHEN 'retryable' THEN 'waiting_retry' ELSE 'queued' END;
 -- Queue rescue/cancellation can finish without re-entering the worker. Close
 -- the service lock in the same transaction, preserving any proven outcome.
 IF NEW.kind='system_control_service' AND NEW.state::text IN ('completed','discarded','cancelled') THEN
  UPDATE server_operations SET
   status=CASE WHEN NEW.state::text='cancelled' AND status IN ('pending','awaiting_confirmation') THEN 'cancelled' ELSE 'failed' END,
   result=result-'stage',
   last_error=CASE WHEN NEW.state::text='cancelled' AND status IN ('pending','awaiting_confirmation') THEN '' ELSE 'Service execution ended without a verified outcome. Check current service state before trying again.' END,
   completed_at=COALESCE(completed_at,now()),updated_at=now()
  WHERE operation_id=NEW.args->>'operation_id' AND category='services' AND target_type='server_service' AND status IN ('pending','running','awaiting_confirmation');
 END IF;
 -- River completion describes queue execution. Domain workers may finish
 -- without retrying a failed command, or cancel after persisting a terminal failure.
 IF NEW.state::text IN ('completed','cancelled') OR (NEW.kind='system_control_service' AND NEW.state::text='discarded') THEN
  CASE NEW.kind
   WHEN 'issue_cert' THEN
    IF NEW.state::text='cancelled' AND NEW.args->>'after_provisioning'='true' AND EXISTS(SELECT 1 FROM sites WHERE id=rid AND tls_status='failed' AND updated_at>=COALESCE(NEW.attempted_at,NEW.created_at)) THEN op_state:='failed'; END IF;
   WHEN 'run_scheduled_task' THEN
    IF EXISTS(SELECT 1 FROM scheduled_task_runs WHERE id=nakpanel_operation_arg_id(NEW.args,'run_id') AND status IN ('failed','timed_out')) THEN op_state:='failed'; END IF;
   WHEN 'deploy_php_release','rollback_php_release' THEN
    IF EXISTS(SELECT 1 FROM php_deployments WHERE id=nakpanel_operation_arg_id(NEW.args,'deployment_id') AND status='failed') THEN op_state:='failed'; END IF;
   WHEN 'wordpress_operation' THEN
    IF EXISTS(SELECT 1 FROM wordpress_operations WHERE id=nakpanel_operation_arg_id(NEW.args,'operation_id') AND status='failed') THEN op_state:='failed'; END IF;
   WHEN 'run_staging_operation' THEN
    IF EXISTS(SELECT 1 FROM staging_operations WHERE id=nakpanel_operation_arg_id(NEW.args,'operation_id') AND status='failed') THEN op_state:='failed'; END IF;
   WHEN 'mail_import' THEN
    IF EXISTS(SELECT 1 FROM mail_imports WHERE id=NEW.args->>'import_id' AND state='failed') THEN op_state:='failed'; END IF;
   WHEN 'system_control_service' THEN
    SELECT CASE status WHEN 'succeeded' THEN 'succeeded' WHEN 'failed' THEN 'failed' WHEN 'cancelled' THEN 'cancelled' ELSE 'failed' END INTO op_state FROM server_operations WHERE operation_id=NEW.args->>'operation_id';
    op_state:=COALESCE(op_state,'failed');
   ELSE NULL;
  END CASE;
 END IF;
 linked_id:=nakpanel_operation_arg_id(NEW.metadata,'nakpanel_operation_id');
 IF linked_id>0 THEN
  SELECT id,intent_revision INTO op_id,revision FROM operations WHERE id=linked_id AND resource_kind=rk AND resource_id=rid FOR UPDATE;
  IF op_id IS NULL THEN RAISE EXCEPTION 'invalid logical operation reference'; END IF;
 ELSE
  INSERT INTO operations(operation_key,kind,resource_kind,resource_id,title,trigger,intent_revision)
   VALUES('river:'||NEW.id,NEW.kind,rk,rid,label,CASE WHEN NEW.args->>'automated'='true' THEN 'scheduled' ELSE 'manual' END,revision)
   ON CONFLICT(operation_key) DO UPDATE SET operation_key=EXCLUDED.operation_key RETURNING id INTO op_id;
 END IF;
 UPDATE operations SET state=op_state,stage=CASE WHEN op_state='waiting_retry' THEN 'Waiting for automatic retry' WHEN op_state='running' THEN 'Working' ELSE '' END,updated_at=now() WHERE id=op_id;
 IF NEW.attempt=0 OR NEW.state::text IN ('running','completed','discarded','cancelled','retryable') THEN
  UPDATE operation_attempts SET state='failed',error_code='interrupted',finished_at=now() WHERE operation_id=op_id AND finished_at IS NULL AND river_job_id=NEW.id AND river_attempt<NEW.attempt;
  attempt_state:=CASE WHEN NEW.state::text='retryable' THEN 'failed' ELSE op_state END;
  INSERT INTO operation_attempts(operation_id,number,river_job_id,river_attempt,state,error_code,started_at,finished_at)
   SELECT op_id,COALESCE(max(number),0)+1,NEW.id,GREATEST(NEW.attempt,1),attempt_state,CASE WHEN attempt_state='failed' THEN 'worker_failed' ELSE '' END,COALESCE(NEW.attempted_at,now()),CASE WHEN attempt_state IN ('succeeded','failed','cancelled') THEN now() ELSE NULL END FROM operation_attempts WHERE operation_id=op_id
   ON CONFLICT(river_job_id,river_attempt) DO UPDATE SET state=EXCLUDED.state,error_code=EXCLUDED.error_code,started_at=CASE WHEN operation_attempts.state='queued' THEN EXCLUDED.started_at ELSE operation_attempts.started_at END,finished_at=EXCLUDED.finished_at WHERE operation_attempts.finished_at IS NULL;
 END IF;
 INSERT INTO operation_events(event_key,resource_kind,resource_id,kind,operation_id,summary)
  VALUES('job:'||NEW.id||':'||NEW.attempt||':'||NEW.state,rk,rid,'task.'||op_state,op_id,label||CASE op_state WHEN 'succeeded' THEN ' completed' WHEN 'failed' THEN ' failed' WHEN 'cancelled' THEN ' cancelled' WHEN 'waiting_retry' THEN ' is waiting to retry' WHEN 'running' THEN ' started' ELSE ' queued' END)
  ON CONFLICT(event_key) DO NOTHING RETURNING id INTO event_id;
  incident_kind:=CASE NEW.kind WHEN 'create_backup' THEN 'backup' WHEN 'issue_cert' THEN 'tls' WHEN 'install_custom_cert' THEN 'tls' WHEN 'create_site' THEN 'hosting' WHEN 'configure_mail' THEN 'mail' WHEN 'configure_webmail' THEN 'mail' WHEN 'configure_dns_zone' THEN 'dns' ELSE 'operation_failed' END;
  incident_condition:=CASE incident_kind WHEN 'backup' THEN 'protection' WHEN 'tls' THEN 'certificate' WHEN 'hosting' THEN 'readiness' WHEN 'mail' THEN 'readiness' WHEN 'dns' THEN 'configuration' ELSE NEW.kind END;
  -- Authorization stays at the owning resource, but independent subjects
  -- within it must not share acknowledgement, recurrence or recovery.
  IF incident_kind='operation_failed' THEN
   IF NEW.kind='run_scheduled_task' THEN
    SELECT task_id INTO subject_id FROM scheduled_task_runs WHERE id=nakpanel_operation_arg_id(NEW.args,'run_id');
    incident_condition:=NEW.kind||':task:'||COALESCE(subject_id,nakpanel_operation_arg_id(NEW.args,'run_id'));
   ELSIF NEW.kind='server_backup' THEN
    SELECT destination_id INTO subject_id FROM server_backups WHERE id=nakpanel_operation_arg_id(NEW.args,'server_backup_id');
    incident_condition:=NEW.kind||CASE WHEN subject_id IS NULL THEN ':backup:'||nakpanel_operation_arg_id(NEW.args,'server_backup_id') ELSE ':destination:'||subject_id END;
   ELSIF NEW.kind='create_database' THEN incident_condition:=NEW.kind||':'||nakpanel_operation_arg_id(NEW.args,'database_id');
   ELSIF NEW.kind IN ('deploy_php_release','rollback_php_release') THEN incident_condition:=NEW.kind||':'||nakpanel_operation_arg_id(NEW.args,'application_id');
   ELSIF NEW.kind='wordpress_operation' THEN incident_condition:=NEW.kind||':'||nakpanel_operation_arg_id(NEW.args,'instance_id');
   ELSIF NEW.kind='restore_backup' THEN incident_condition:=NEW.kind||':'||nakpanel_operation_arg_id(NEW.args,'backup_id');
   ELSIF NEW.kind='mail_import' THEN incident_condition:=NEW.kind||':'||COALESCE(NEW.args->>'import_id','');
   ELSIF NEW.kind='system_control_service' THEN incident_condition:=NEW.kind||':'||COALESCE(NEW.args->>'service_id','unknown');
   END IF;
  END IF;
 IF op_state<>'failed' AND event_id IS NOT NULL THEN
  UPDATE issues SET generation=generation+1,latest_event_id=event_id,operation_id=op_id,last_check_status='unknown',updated_at=now() WHERE resource_kind=rk AND resource_id=rid AND kind=incident_kind AND condition=incident_condition AND resolved_at IS NULL RETURNING id INTO incident_id;
  IF incident_id IS NOT NULL THEN UPDATE operation_events SET issue_id=incident_id WHERE id=event_id; END IF;
 END IF;
 IF op_state='failed' AND event_id IS NOT NULL THEN
  INSERT INTO issues(resource_kind,resource_id,kind,condition,severity,title,summary,latest_event_id,intent_revision,operation_id,observed_at,previous_issue_id)
   VALUES(rk,rid,incident_kind,incident_condition,'critical',label||' needs attention','The operation failed. Review its prerequisites and current resource settings.',event_id,revision,op_id,now(),(SELECT id FROM issues WHERE resource_kind=rk AND resource_id=rid AND kind=incident_kind AND condition=incident_condition AND resolved_at IS NOT NULL ORDER BY id DESC LIMIT 1))
   ON CONFLICT(resource_kind,resource_id,kind,condition) WHERE resolved_at IS NULL DO UPDATE SET generation=issues.generation+1,occurrences=issues.occurrences+1,latest_event_id=EXCLUDED.latest_event_id,intent_revision=EXCLUDED.intent_revision,operation_id=EXCLUDED.operation_id,title=EXCLUDED.title,summary=EXCLUDED.summary,severity='critical',observed_at=now(),last_check_status='unknown',updated_at=now(),state=CASE WHEN issues.acknowledged_at IS NULL THEN 'open' ELSE 'acknowledged' END RETURNING id INTO incident_id;
  UPDATE operation_events SET issue_id=incident_id WHERE id=event_id;
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION nakpanel_install_operations_recorder() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF to_regclass('river_job') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS nakpanel_operations_recorder ON river_job;
  CREATE TRIGGER nakpanel_operations_recorder AFTER INSERT OR UPDATE OF state,attempt ON river_job FOR EACH ROW EXECUTE FUNCTION nakpanel_record_operation_job();
 END IF;
END;
$$;
-- +goose StatementEnd
SELECT nakpanel_install_operations_recorder();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF to_regclass('river_job') IS NOT NULL THEN DROP TRIGGER IF EXISTS nakpanel_operations_recorder ON river_job; END IF; END $$;
-- +goose StatementEnd
DROP FUNCTION nakpanel_install_operations_recorder();
DROP FUNCTION nakpanel_record_operation_job();
DROP FUNCTION nakpanel_operation_arg_id(jsonb,text);
ALTER TABLE operation_attempts DROP CONSTRAINT operation_attempts_source_execution;
ALTER TABLE operation_attempts DROP COLUMN river_attempt;
ALTER TABLE operation_attempts ADD CONSTRAINT operation_attempts_river_job_id_key UNIQUE(river_job_id);
ALTER TABLE issues DROP COLUMN last_check_status;
ALTER TABLE issues DROP COLUMN last_check_at;
