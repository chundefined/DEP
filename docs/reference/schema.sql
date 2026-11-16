-- =============================================================================
-- DEP - Detection Engineering Platform
-- PostgreSQL schema (index derived from Git + metric series + audit)
-- Version: 1.0.0
--
-- NOTE: Git is the source of truth. Tables marked [REBUILDABLE] can be
-- rebuilt from the repository. Those marked [PERSISTENT] cannot, and require
-- their own backup (metrics, audit log, snapshots).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ---------------------------------------------------------------------------
-- ENUMS
-- ---------------------------------------------------------------------------

CREATE TYPE lifecycle_status AS ENUM (
    'idea','draft','in_development','in_review','testing',
    'production_candidate','active','tuning','degraded',
    'disabled','deprecated','retired');

CREATE TYPE severity_level AS ENUM ('info','low','medium','high','critical');
CREATE TYPE confidence_level AS ENUM ('low','medium','high');

CREATE TYPE detection_type AS ENUM (
    'signature','threshold','anomaly','correlation','behavioral',
    'ml','threat_intel','hunting');

CREATE TYPE implementation_type AS ENUM (
    'generated','generated_customized','native');

CREATE TYPE implementation_status AS ENUM (
    'draft','not_deployed','active','legacy','deprecated','disabled','failed');

CREATE TYPE drift_status AS ENUM (
    'in_sync','local_ahead','remote_ahead','diverged','unknown','not_deployed');

CREATE TYPE coverage_level AS ENUM (
    'none','minimal','partial','significant','complete');

CREATE TYPE layer_strength AS ENUM ('primary','supporting','partial');

CREATE TYPE validation_type AS ENUM (
    'data_availability','schema_validation','syntax_validation','logic_review',
    'unit_test','regression_test','historical_backtest','noise_analysis',
    'tuning_validation','performance_test','atomic_test','red_team',
    'purple_team','deployment_validation','production_validation');

CREATE TYPE validation_result AS ENUM (
    'pass','fail','partial','blocked','not_applicable');

CREATE TYPE finding_type AS ENUM (
    'noise','schema','data_quality','data_gap','logic_error','coverage_gap',
    'performance','drift','governance','documentation','evasion',
    'duplication','dependency');

CREATE TYPE finding_status AS ENUM (
    'open','acknowledged','in_progress','resolved','accepted_risk','wont_fix');

CREATE TYPE deployment_action AS ENUM (
    'create','update','enable','disable','delete','rollback');

CREATE TYPE deployment_status AS ENUM (
    'pending','in_progress','success','failed','rolled_back','partial');

CREATE TYPE metric_scope AS ENUM (
    'detection','implementation','program','platform','team');

CREATE TYPE evidence_type AS ENUM (
    'screenshot','query_output','log_sample','csv','json','pcap',
    'report','link','video');

CREATE TYPE relationship_type AS ENUM (
    'supersedes','superseded_by','duplicates','complements','depends_on',
    'variant_of','broader_than','narrower_than');

CREATE TYPE exception_type AS ENUM (
    'exclusion','allowlist','threshold_adjust','suppression','time_window');

CREATE TYPE ingest_status AS ENUM ('active','degraded','absent','unknown');
CREATE TYPE field_reliability AS ENUM ('reliable','partial','unreliable','absent','unknown');

-- ---------------------------------------------------------------------------
-- TAXONOMÍAS  [REBUILDABLE]
-- ---------------------------------------------------------------------------

CREATE TABLE platform (
    id                      text PRIMARY KEY,
    name                    text NOT NULL,
    type                    text NOT NULL,          -- siem|edr|ndr|cnapp|waf|dlp
    query_language          text NOT NULL,
    sigmaforge_backend      text,
    vendor                  text,
    version                 text,
    supports_deployment_api boolean NOT NULL DEFAULT false,
    supports_query_api      boolean NOT NULL DEFAULT false,
    capabilities            jsonb NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE environment (
    id                          text PRIMARY KEY,
    name                        text NOT NULL,
    platform_id                 text NOT NULL REFERENCES platform(id),
    tier                        text NOT NULL,      -- dev|test|staging|prod
    region                      text,
    workspace_ref               text,
    promotion_target_id         text REFERENCES environment(id),
    requires_approval           boolean NOT NULL DEFAULT false,
    data_retention_days         integer,
    is_authoritative_for_metrics boolean NOT NULL DEFAULT false,
    connector_id                text
);

CREATE TABLE detection_layer (
    id                  text PRIMARY KEY,
    name                text NOT NULL,
    description         text,
    weight              numeric(4,2) NOT NULL DEFAULT 1.0,
    target_coverage_pct integer
);

CREATE TABLE data_source (
    id                      text PRIMARY KEY,
    name                    text NOT NULL,
    category                text NOT NULL,
    attack_data_source      text,
    attack_data_component   text,
    criticality             text,
    owner_id                text
);

CREATE TABLE log_source (
    id                  text PRIMARY KEY,
    data_source_id      text NOT NULL REFERENCES data_source(id),
    platform_id         text NOT NULL REFERENCES platform(id),
    table_or_stream     text NOT NULL,
    event_ids           text[] DEFAULT '{}',
    ingest_status       ingest_status NOT NULL DEFAULT 'unknown',
    last_seen_at        timestamptz,
    avg_daily_volume    bigint,
    retention_days      integer,
    checked_at          timestamptz
);

CREATE TABLE schema_field (
    id                  bigserial PRIMARY KEY,
    log_source_id       text NOT NULL REFERENCES log_source(id) ON DELETE CASCADE,
    field_name          text NOT NULL,
    data_type           text,
    reliability         field_reliability NOT NULL DEFAULT 'unknown',
    reliability_notes   text,
    populated_ratio     numeric(5,4),
    verified_at         timestamptz,
    ecs_mapping         text,
    asim_mapping        text,
    ocsf_mapping        text,
    UNIQUE (log_source_id, field_name)
);

CREATE TABLE owner (
    id                  text PRIMARY KEY,
    type                text NOT NULL,   -- team|individual|vendor
    name                text NOT NULL,
    email               text,
    chat_channel        text,
    escalation_contact  text,
    responsibilities    text[] DEFAULT '{}',
    sla_response_days   integer
);

CREATE TABLE app_user (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username            text UNIQUE NOT NULL,
    email               text,
    display_name        text,
    role                text NOT NULL DEFAULT 'viewer',
    owner_id            text REFERENCES owner(id),
    active              boolean NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE attack_technique (
    technique_id        text PRIMARY KEY,           -- T1187 / T1187.001
    attack_version      text NOT NULL,
    name                text NOT NULL,
    tactic_ids          text[] NOT NULL,
    parent_technique    text REFERENCES attack_technique(technique_id),
    is_subtechnique     boolean NOT NULL DEFAULT false,
    platforms           text[],
    data_sources        text[],
    deprecated          boolean NOT NULL DEFAULT false,
    url                 text
);

-- ---------------------------------------------------------------------------
-- DETECTION  [REBUILDABLE]
-- ---------------------------------------------------------------------------

CREATE TABLE detection (
    id                          text PRIMARY KEY,       -- DET-0003
    uuid                        uuid UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                   text NOT NULL DEFAULT 'default',   -- reservado
    name                        text NOT NULL,
    slug                        text NOT NULL,
    version                     text NOT NULL,
    status                      lifecycle_status NOT NULL DEFAULT 'draft',
    description                 text NOT NULL,
    severity                    severity_level NOT NULL DEFAULT 'medium',
    confidence                  confidence_level,
    risk_score                  integer CHECK (risk_score BETWEEN 0 AND 100),
    detection_type              detection_type NOT NULL DEFAULT 'signature',
    alert_disposition           text,
    fp_rate_expected            text,
    tlp                         text,
    visibility                  text,
    tags                        text[] DEFAULT '{}',
    source_origin               text,
    source_reference            text,
    source_template_version     text,
    owner_id                    text REFERENCES owner(id),
    author                      text,
    maintainer                  text,
    approver                    text,
    review_cadence_days         integer DEFAULT 180,
    last_reviewed_at            date,
    next_review_due             date,
    deprecation_reason          text,
    deprecation_date            date,
    replaced_by                 text REFERENCES detection(id),
    git_path                    text NOT NULL,
    git_commit                  text,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    search_vector               tsvector
);

CREATE INDEX idx_detection_status        ON detection(status);
CREATE INDEX idx_detection_severity      ON detection(severity);
CREATE INDEX idx_detection_owner         ON detection(owner_id);
CREATE INDEX idx_detection_tags          ON detection USING gin(tags);
CREATE INDEX idx_detection_search        ON detection USING gin(search_vector);
CREATE INDEX idx_detection_name_trgm     ON detection USING gin(name gin_trgm_ops);

CREATE TABLE detection_intent (
    detection_id        text PRIMARY KEY REFERENCES detection(id) ON DELETE CASCADE,
    summary             text NOT NULL,
    hypothesis          text,
    adversary_behavior  text[] NOT NULL DEFAULT '{}',
    preconditions       text[] DEFAULT '{}',
    assumptions         text[] DEFAULT '{}',
    scope_included      text[] DEFAULT '{}',
    scope_excluded      text[] DEFAULT '{}',
    evasion_notes       text,
    kill_chain_phase    text[] DEFAULT '{}',
    attack_surface      text[] DEFAULT '{}'
);

CREATE TABLE mitre_mapping (
    id                      bigserial PRIMARY KEY,
    detection_id            text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    tactic                  text NOT NULL,
    technique               text NOT NULL,
    subtechnique            text,
    attack_version          text NOT NULL,
    coverage_level          coverage_level NOT NULL DEFAULT 'partial',
    detection_confidence    confidence_level,
    is_primary              boolean NOT NULL DEFAULT false,
    notes                   text,
    UNIQUE (detection_id, technique, subtechnique)
);
CREATE INDEX idx_mitre_technique ON mitre_mapping(technique);

CREATE TABLE detection_layer_map (
    detection_id    text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    layer_id        text NOT NULL REFERENCES detection_layer(id),
    strength        layer_strength NOT NULL DEFAULT 'primary',
    PRIMARY KEY (detection_id, layer_id)
);

CREATE TABLE detection_data_source (
    detection_id    text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    data_source_id  text NOT NULL REFERENCES data_source(id),
    is_required     boolean NOT NULL DEFAULT true,
    required_fields text[] DEFAULT '{}',
    PRIMARY KEY (detection_id, data_source_id)
);

CREATE TABLE detection_relationship (
    id                  bigserial PRIMARY KEY,
    from_detection_id   text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    to_detection_id     text REFERENCES detection(id) ON DELETE CASCADE,
    asset_ref           text,
    type                relationship_type NOT NULL,
    notes               text
);

CREATE TABLE threat_mapping (
    id              bigserial PRIMARY KEY,
    detection_id    text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    type            text NOT NULL,      -- actor|campaign|malware|tool|cve|report
    identifier      text NOT NULL,
    name            text,
    relevance       text,
    source          text
);

CREATE TABLE documentation (
    id                      bigserial PRIMARY KEY,
    detection_id            text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    doc_type                text NOT NULL,
    file_path               text NOT NULL,
    content                 text,
    format                  text NOT NULL DEFAULT 'markdown',
    language                text,
    word_count              integer,
    has_required_sections   boolean,
    completeness_score      numeric(4,3),
    last_reviewed_at        timestamptz,
    UNIQUE (detection_id, doc_type)
);

CREATE TABLE runbook (
    detection_id                text PRIMARY KEY REFERENCES detection(id) ON DELETE CASCADE,
    triage_steps                jsonb DEFAULT '[]'::jsonb,
    escalation_criteria         text,
    containment_actions         text[] DEFAULT '{}',
    soar_playbook_ref           text,
    estimated_triage_minutes    integer
);

-- ---------------------------------------------------------------------------
-- IMPLEMENTATION  [REBUILDABLE]
-- ---------------------------------------------------------------------------

CREATE TABLE implementation (
    id                  text PRIMARY KEY,       -- IMP-0003-SENTINEL-PROD
    detection_id        text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    platform_id         text NOT NULL REFERENCES platform(id),
    environment_id      text NOT NULL REFERENCES environment(id),
    type                implementation_type NOT NULL,
    status              implementation_status NOT NULL DEFAULT 'draft',
    enabled             boolean NOT NULL DEFAULT false,   -- estado REAL (connector)
    enabled_declared    boolean NOT NULL DEFAULT false,   -- estado DECLARADO (git)
    version             text NOT NULL,
    inherits_from       text REFERENCES implementation(id),
    native_rule_id      text,
    native_rule_name    text,
    schedule            jsonb,
    threshold           jsonb,
    suppression         jsonb,
    entity_mappings     jsonb DEFAULT '[]'::jsonb,
    custom_details      jsonb DEFAULT '{}'::jsonb,
    alert_grouping      jsonb,
    performance         jsonb,
    sigma_backed        boolean NOT NULL DEFAULT false,
    sigma_hash          text,
    generated_at        timestamptz,
    generator_version   text,
    customized          boolean NOT NULL DEFAULT false,
    drift_status        drift_status NOT NULL DEFAULT 'unknown',
    drift_detail        jsonb,
    drift_detected_at   timestamptz,
    last_deployed_at    timestamptz,
    last_synced_at      timestamptz,
    deprecation_notes   text,
    notes               text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (detection_id, platform_id, environment_id)
);

CREATE INDEX idx_impl_detection ON implementation(detection_id);
CREATE INDEX idx_impl_drift     ON implementation(drift_status);
CREATE INDEX idx_impl_env       ON implementation(environment_id, status);

CREATE TABLE detection_logic (
    id                      bigserial PRIMARY KEY,
    implementation_id       text NOT NULL REFERENCES implementation(id) ON DELETE CASCADE,
    language                text NOT NULL,
    code                    text NOT NULL,          -- literal, sin transformar
    code_hash               text NOT NULL,
    file_path               text NOT NULL,
    line_count              integer,
    complexity_score        integer,
    uses_functions          text[] DEFAULT '{}',
    external_dependencies   text[] DEFAULT '{}',
    parsed_ok               boolean,
    lint_warnings           text[] DEFAULT '{}',
    is_current              boolean NOT NULL DEFAULT true,
    created_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_logic_impl_current ON detection_logic(implementation_id) WHERE is_current;

CREATE TABLE sigma_rule (
    detection_id            text PRIMARY KEY REFERENCES detection(id) ON DELETE CASCADE,
    sigma_yaml              text NOT NULL,
    sigma_id                uuid,
    sigma_hash              text NOT NULL,
    is_authoritative        boolean NOT NULL DEFAULT false,
    translation_coverage    text,
    untranslatable_parts    text[] DEFAULT '{}',
    file_path               text
);

CREATE TABLE enrichment_asset (
    id                          text PRIMARY KEY,
    type                        text NOT NULL,
    platform_id                 text NOT NULL REFERENCES platform(id),
    native_name                 text,
    owner_id                    text REFERENCES owner(id),
    refresh_frequency           text,
    last_updated_at             timestamptz,
    row_count                   bigint,
    staleness_threshold_days    integer DEFAULT 30,
    checked_at                  timestamptz
);

CREATE TABLE implementation_enrichment (
    implementation_id   text NOT NULL REFERENCES implementation(id) ON DELETE CASCADE,
    asset_id            text NOT NULL REFERENCES enrichment_asset(id),
    is_required         boolean NOT NULL DEFAULT true,
    purpose             text,
    PRIMARY KEY (implementation_id, asset_id)
);

CREATE TABLE exception_rule (
    id                  text PRIMARY KEY,
    implementation_id   text NOT NULL REFERENCES implementation(id) ON DELETE CASCADE,
    finding_id          text,
    type                exception_type NOT NULL,
    expression          text,
    expression_file     text,
    justification       text NOT NULL,
    risk_accepted       text NOT NULL,
    approved_by         text,
    approved_at         date,
    expires_at          date,
    review_required_at  date,
    scope               text DEFAULT 'global',
    active              boolean NOT NULL DEFAULT true
);
CREATE INDEX idx_exception_expiry ON exception_rule(expires_at) WHERE active;

-- ---------------------------------------------------------------------------
-- VALIDATION  [REBUILDABLE]
-- ---------------------------------------------------------------------------

CREATE TABLE test_definition (
    id                  text PRIMARY KEY,
    detection_id        text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    name                text NOT NULL,
    type                validation_type NOT NULL,
    description         text,
    given_clause        text NOT NULL,
    when_clause         text NOT NULL,
    then_clause         text NOT NULL,
    test_data_ref       text,
    expected_match_count integer,
    expected_fields     text[] DEFAULT '{}',
    is_negative_test    boolean NOT NULL DEFAULT false,
    automation_status   text NOT NULL DEFAULT 'manual',
    runner              text,
    frequency           text,
    atomic_test_ref     text,
    enabled             boolean NOT NULL DEFAULT true
);

CREATE TABLE validation_run (
    id                  text PRIMARY KEY,           -- VAL-2026-0812
    detection_id        text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    implementation_id   text REFERENCES implementation(id) ON DELETE SET NULL,
    test_id             text REFERENCES test_definition(id) ON DELETE SET NULL,
    type                validation_type NOT NULL,
    executed_at         timestamptz NOT NULL,
    engineer            text NOT NULL,
    environment_id      text REFERENCES environment(id),
    query_version       text,
    query_hash          text,
    input_dataset       jsonb NOT NULL DEFAULT '{}'::jsonb,
    expected_result     text NOT NULL,
    actual_result       text NOT NULL,
    result              validation_result NOT NULL,
    metrics             jsonb DEFAULT '{}'::jsonb,
    duration_ms         integer,
    automated           boolean NOT NULL DEFAULT false,
    tooling             text,
    notes               text,
    signature           text,
    file_path           text
);
CREATE INDEX idx_val_detection  ON validation_run(detection_id, executed_at DESC);
CREATE INDEX idx_val_type       ON validation_run(type, result);

CREATE TABLE evidence (
    id              text PRIMARY KEY,               -- EVD-2026-1187
    type            evidence_type NOT NULL,
    title           text NOT NULL,
    file_path       text,
    storage         text NOT NULL DEFAULT 'git',    -- git|lfs|s3
    external_uri    text,
    sha256          text NOT NULL,
    size_bytes      bigint,
    captured_at     timestamptz NOT NULL,
    captured_by     text NOT NULL,
    redacted        boolean NOT NULL DEFAULT false,
    redaction_notes text,
    retention_until date,
    entity_type     text NOT NULL,                  -- validation_run|finding|deployment
    entity_id       text NOT NULL
);
CREATE INDEX idx_evidence_entity ON evidence(entity_type, entity_id);

CREATE TABLE finding (
    id                  text PRIMARY KEY,           -- FND-0001
    detection_id        text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    implementation_id   text REFERENCES implementation(id) ON DELETE SET NULL,
    validation_run_id   text REFERENCES validation_run(id) ON DELETE SET NULL,
    type                finding_type NOT NULL,
    title               text NOT NULL,
    observation         text NOT NULL,
    pattern             text,
    severity            severity_level NOT NULL,
    impact              text,
    recommendation      text NOT NULL,
    status              finding_status NOT NULL DEFAULT 'open',
    assigned_to         text,
    opened_at           timestamptz NOT NULL DEFAULT now(),
    resolved_at         timestamptz,
    resolution          text,
    resolution_ref      text,
    blocks_promotion    boolean NOT NULL DEFAULT false,
    recurrence_count    integer NOT NULL DEFAULT 0,
    risk_accepted_by    text,
    risk_accepted_until date,
    auto_generated      boolean NOT NULL DEFAULT false,
    rule_code           text,                       -- F-01..F-15
    file_path           text
);
CREATE INDEX idx_finding_status   ON finding(status, severity);
CREATE INDEX idx_finding_blocking ON finding(detection_id) WHERE blocks_promotion AND status IN ('open','acknowledged','in_progress');

-- ---------------------------------------------------------------------------
-- DEPLOYMENT & VERSIONING  [REBUILDABLE parcialmente]
-- ---------------------------------------------------------------------------

CREATE TABLE deployment (
    id                          text PRIMARY KEY,   -- DEP-2026-0311
    implementation_id           text NOT NULL REFERENCES implementation(id) ON DELETE CASCADE,
    environment_id              text NOT NULL REFERENCES environment(id),
    action                      deployment_action NOT NULL,
    from_version                text,
    to_version                  text NOT NULL,
    git_commit                  text NOT NULL,
    triggered_by                text NOT NULL,
    trigger_type                text NOT NULL,
    approved_by                 text,
    approval_ref                text,
    started_at                  timestamptz NOT NULL,
    finished_at                 timestamptz,
    status                      deployment_status NOT NULL DEFAULT 'pending',
    error_message               text,
    dry_run                     boolean NOT NULL DEFAULT false,
    rollback_of                 text REFERENCES deployment(id),
    post_deploy_validation_id   text REFERENCES validation_run(id),
    gates_evaluated             jsonb DEFAULT '[]'::jsonb
);
CREATE INDEX idx_deploy_impl ON deployment(implementation_id, started_at DESC);

CREATE TABLE entity_version (
    id              bigserial PRIMARY KEY,
    entity_type     text NOT NULL,
    entity_id       text NOT NULL,
    version         text NOT NULL,
    git_commit      text NOT NULL,
    git_tag         text,
    change_type     text NOT NULL,
    change_category text NOT NULL,
    changelog       text NOT NULL,
    author          text NOT NULL,
    content_hash    text NOT NULL,
    breaking        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_type, entity_id, version)
);

CREATE TABLE review (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id    text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    type            text NOT NULL,
    reviewer        text NOT NULL,
    decision        text NOT NULL,
    comments        text,
    checklist       jsonb DEFAULT '{}'::jsonb,
    reviewed_at     timestamptz NOT NULL DEFAULT now(),
    git_pr_ref      text
);

-- ---------------------------------------------------------------------------
-- METRICS AND POSTURE  [PERSISTENT - requires its own backup]
-- ---------------------------------------------------------------------------

CREATE TABLE metric (
    id              bigserial PRIMARY KEY,
    scope           metric_scope NOT NULL,
    subject_id      text,
    metric_key      text NOT NULL,
    value           numeric NOT NULL,
    unit            text,
    period_start    timestamptz NOT NULL,
    period_end      timestamptz NOT NULL,
    granularity     text NOT NULL,
    source          text NOT NULL,
    environment_id  text REFERENCES environment(id),
    confidence      text,
    collected_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_metric_lookup ON metric(scope, subject_id, metric_key, period_end DESC);
-- Recommendation: partition by period_end range if the volume grows.

CREATE TABLE detection_score (
    id                          bigserial PRIMARY KEY,
    detection_id                text NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    computed_at                 timestamptz NOT NULL DEFAULT now(),
    coverage                    integer NOT NULL,
    quality                     integer NOT NULL,
    health                      integer NOT NULL,
    effectiveness               integer NOT NULL,
    governance                  integer NOT NULL,
    layer_coverage              integer NOT NULL,
    production_effectiveness    integer NOT NULL,
    overall                     integer NOT NULL,
    band                        text NOT NULL,
    components                  jsonb NOT NULL DEFAULT '{}'::jsonb,  -- desglose
    caps_applied                text[] DEFAULT '{}',
    is_current                  boolean NOT NULL DEFAULT true
);
CREATE INDEX idx_score_current ON detection_score(detection_id) WHERE is_current;
CREATE INDEX idx_score_history ON detection_score(detection_id, computed_at DESC);

CREATE TABLE posture_snapshot (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    taken_at            timestamptz NOT NULL DEFAULT now(),
    scope               text NOT NULL DEFAULT 'program',
    scope_key           text,
    scores              jsonb NOT NULL,
    overall             integer NOT NULL,
    detection_count     integer NOT NULL,
    breakdown           jsonb NOT NULL DEFAULT '{}'::jsonb,
    git_commit          text
);
CREATE INDEX idx_snapshot_time ON posture_snapshot(scope, taken_at DESC);

CREATE TABLE coverage_item (
    id                  bigserial PRIMARY KEY,
    dimension           text NOT NULL,          -- mitre_technique|data_source|layer|platform
    key                 text NOT NULL,
    profile             text,                   -- applied threat profile
    detection_ids       text[] DEFAULT '{}',
    coverage_level      coverage_level NOT NULL DEFAULT 'none',
    is_gap              boolean NOT NULL DEFAULT false,
    priority            text,
    justification       text,
    accepted            boolean NOT NULL DEFAULT false,
    accepted_by         text,
    computed_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (dimension, key, profile)
);

-- ---------------------------------------------------------------------------
-- AUDIT  [PERSISTENT - append only]
-- ---------------------------------------------------------------------------

CREATE TABLE audit_event (
    id              bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor           text NOT NULL,
    action          text NOT NULL,
    entity_type     text NOT NULL,
    entity_id       text NOT NULL,
    before_state    jsonb,
    after_state     jsonb,
    source          text NOT NULL,      -- ui|api|git|connector|pipeline
    ip_address      inet,
    request_id      text,
    git_commit      text
);
CREATE INDEX idx_audit_entity ON audit_event(entity_type, entity_id, occurred_at DESC);
CREATE INDEX idx_audit_actor  ON audit_event(actor, occurred_at DESC);

-- Prevent modification of the audit log
CREATE RULE audit_no_update AS ON UPDATE TO audit_event DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_event DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- OPERACIONES
-- ---------------------------------------------------------------------------

CREATE TABLE connector_state (
    connector_id        text PRIMARY KEY,
    platform_id         text NOT NULL REFERENCES platform(id),
    status              text NOT NULL DEFAULT 'unknown',   -- ok|degraded|down
    capabilities        text[] DEFAULT '{}',
    last_success_at     timestamptz,
    last_attempt_at     timestamptz,
    last_error          text,
    consecutive_failures integer NOT NULL DEFAULT 0
);

CREATE TABLE orphan_rule (
    id                  bigserial PRIMARY KEY,
    environment_id      text NOT NULL REFERENCES environment(id),
    native_rule_id      text NOT NULL,
    native_rule_name    text,
    enabled             boolean,
    last_modified_at    timestamptz,
    last_modified_by    text,
    alert_count_90d     bigint,
    query_excerpt       text,
    discovered_at       timestamptz NOT NULL DEFAULT now(),
    disposition         text,       -- pending|adopted|retire|ignored
    disposition_reason  text,
    UNIQUE (environment_id, native_rule_id)
);

CREATE TABLE job (
    id              text PRIMARY KEY,
    type            text NOT NULL,
    status          text NOT NULL DEFAULT 'queued',
    payload         jsonb,
    result          jsonb,
    error           text,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

-- ---------------------------------------------------------------------------
-- VISTAS ÚTILES
-- ---------------------------------------------------------------------------

CREATE VIEW v_detection_inventory AS
SELECT
    d.id, d.name, d.severity, d.status,
    e.id AS environment_id, p.id AS platform_id,
    i.status AS impl_status, i.enabled, i.version AS impl_version,
    i.drift_status
FROM detection d
LEFT JOIN implementation i ON i.detection_id = d.id
LEFT JOIN environment e ON e.id = i.environment_id
LEFT JOIN platform p ON p.id = i.platform_id
WHERE d.status <> 'retired';

CREATE VIEW v_detection_health AS
SELECT
    d.id, d.name, d.status, s.overall AS score,
    (SELECT count(*) FROM finding f
      WHERE f.detection_id = d.id AND f.status IN ('open','acknowledged','in_progress')) AS open_findings,
    (SELECT count(*) FROM finding f
      WHERE f.detection_id = d.id AND f.blocks_promotion
        AND f.status IN ('open','acknowledged','in_progress')) AS blocking_findings,
    (SELECT max(executed_at) FROM validation_run v WHERE v.detection_id = d.id) AS last_validation,
    d.next_review_due,
    EXISTS (SELECT 1 FROM implementation i
             WHERE i.detection_id = d.id AND i.drift_status IN ('diverged','remote_ahead')) AS has_drift,
    (d.owner_id IS NULL) AS missing_owner,
    NOT EXISTS (SELECT 1 FROM test_definition t WHERE t.detection_id = d.id) AS missing_tests
FROM detection d
LEFT JOIN detection_score s ON s.detection_id = d.id AND s.is_current
WHERE d.status NOT IN ('retired','idea');

CREATE VIEW v_blocking_gates AS
SELECT f.detection_id, f.id AS finding_id, f.type, f.severity, f.title, f.opened_at
FROM finding f
WHERE f.blocks_promotion AND f.status IN ('open','acknowledged','in_progress');

-- ---------------------------------------------------------------------------
-- TRIGGERS
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_detection_touch BEFORE UPDATE ON detection
    FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();
CREATE TRIGGER trg_impl_touch BEFORE UPDATE ON implementation
    FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE OR REPLACE FUNCTION fn_detection_search_vector() RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        setweight(to_tsvector('simple', coalesce(NEW.id,'')), 'A') ||
        setweight(to_tsvector('simple', coalesce(NEW.name,'')), 'A') ||
        setweight(to_tsvector('simple', coalesce(NEW.description,'')), 'B') ||
        setweight(to_tsvector('simple', array_to_string(coalesce(NEW.tags,'{}'),' ')), 'C');
    RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_detection_search BEFORE INSERT OR UPDATE ON detection
    FOR EACH ROW EXECUTE FUNCTION fn_detection_search_vector();

-- Rule R-13: implementation_type consistency
ALTER TABLE implementation ADD CONSTRAINT chk_impl_type_consistency CHECK (
    (type = 'generated'            AND sigma_backed AND NOT customized) OR
    (type = 'generated_customized' AND sigma_backed) OR
    (type = 'native'               AND NOT sigma_backed)
);
