-- +goose Up
-- Only untouched built-in plans are upgraded. Existing subscription snapshots
-- remain unchanged until an operator explicitly synchronizes them.
WITH updated_plans AS (
    UPDATE plans AS p
    SET php_allowlist = '8.4,8.5,8.3',
        default_php_version = '8.4',
        hosting_policy = jsonb_set(
            jsonb_set(p.hosting_policy, '{php,default_version}', to_jsonb('8.4'::text), true),
            '{php,allowed_versions}', '["8.4","8.5","8.3"]'::jsonb, true
        ),
        revision = p.revision + 1,
        updated_at = now()
    WHERE p.reseller_id IS NULL
      AND p.name IN ('Starter', 'Business', 'Pro')
      AND p.revision = 1
      AND p.php_allowlist = '8.3,8.2'
      AND p.default_php_version = '8.3'
      AND p.hosting_policy#>>'{php,default_version}' = '8.3'
      AND p.hosting_policy#>'{php,allowed_versions}' = '["8.3","8.2"]'::jsonb
    RETURNING p.*
), updated_presets AS (
    UPDATE plan_service_presets AS ps
    SET php = jsonb_set(
        jsonb_set(ps.php, '{default_version}', to_jsonb('8.4'::text), true),
        '{allowed_versions}', to_jsonb('8.4,8.5,8.3'::text), true
    )
    FROM updated_plans AS p
    WHERE ps.plan_id = p.id
    RETURNING ps.*
), definitions AS (
    SELECT p.id, p.revision, p.lifecycle_status,
           jsonb_build_object(
               'plan', to_jsonb(p) - 'created_at' - 'updated_at' - 'last_validated_at' - 'readiness_error',
               'presets', jsonb_build_object(
                   'schema_version', COALESCE(ps.schema_version, 1),
                   'hosting', COALESCE(ps.hosting, '{}'::jsonb),
                   'php', COALESCE(ps.php, '{}'::jsonb),
                   'mail', COALESCE(ps.mail, '{}'::jsonb),
                   'dns', COALESCE(ps.dns, '{}'::jsonb),
                   'performance', COALESCE(ps.performance, '{}'::jsonb),
                   'logs', COALESCE(ps.logs, '{}'::jsonb),
                   'applications', COALESCE(ps.applications, '{}'::jsonb)
               )
           ) AS definition
    FROM updated_plans AS p
    LEFT JOIN updated_presets AS ps ON ps.plan_id = p.id
)
INSERT INTO plan_revisions (
    plan_id, revision, lifecycle_status, definition, definition_hash,
    actor_label, change_reason
)
SELECT d.id, d.revision, d.lifecycle_status, d.definition,
       encode(sha256(convert_to(d.definition::text, 'UTF8')), 'hex'),
       'migration', 'Align untouched built-in plans with PHP 8.4 and 8.5'
FROM definitions AS d;

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION 'Cannot reverse immutable plan revisions; restore a pre-migration database backup instead';
END;
$$;
-- +goose StatementEnd
