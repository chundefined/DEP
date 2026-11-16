# 03 - Architecture

---

## 1. Logical architecture (frozen vision)

This is the agreed architecture, formalized:

```mermaid
flowchart TB
    subgraph UI["PRESENTATION LAYER - a single GUI"]
        direction LR
        U1["Detection<br/>Catalog"]
        U2["Detection<br/>Editor"]
        U3["Inventory<br/>& Search"]
        U4["Posture<br/>Dashboard"]
        U5["Validation<br/>& Findings"]
        U6["Reports"]
        U7["Admin /<br/>Connectors"]
    end

    subgraph API["API LAYER"]
        A1["REST / GraphQL API"]
        A2["AuthN / AuthZ (RBAC)"]
        A3["Webhooks & Events"]
    end

    subgraph CORE["DETECTION ENGINE (core)"]
        direction TB
        C1["Detection Service<br/>CRUD, versioning, lifecycle"]
        C2["Sigma Service<br/>canonical model"]
        C3["Translation Service<br/>SigmaForge wrapper"]
        C4["Validation Service<br/>orchestrates tests"]
        C5["Posture Engine<br/>scoring and coverage"]
        C6["Drift Engine<br/>Git vs SIEM vs Sigma"]
        C7["Deployment Service<br/>promotion and rollback"]
        C8["Findings Service"]
        C9["Metrics Collector"]
    end

    subgraph ENGINES["EMBEDDED EXTERNAL ENGINES"]
        E1["Sigma<br/>(model)"]
        E2["SigmaForge<br/>(translation)"]
        E3["RSigma<br/>(testing)"]
        E4["Validators<br/>(schema, data, syntax, perf)"]
    end

    subgraph STORE["PERSISTENCE"]
        S1[("Git Repository<br/><b>SOURCE OF TRUTH</b>")]
        S2[("PostgreSQL<br/>index + series")]
        S3[("Object Storage<br/>evidence")]
        S4[("Cache / Queue<br/>Redis")]
    end

    subgraph CONN["CONNECTORS"]
        N1["Sentinel<br/>Connector"]
        N2["QRadar<br/>Connector"]
        N3["EDR<br/>Connector"]
        N4["Network<br/>Connector"]
        N5["Future<br/>Connectors"]
    end

    subgraph EXT["EXTERNAL SYSTEMS"]
        X1["Microsoft Sentinel<br/>DEV / PROD"]
        X2["IBM QRadar<br/>PROD"]
        X3["EDR / NDR"]
        X4["MITRE ATT&CK<br/>STIX feed"]
        X5["SOAR / Ticketing"]
        X6["IdP (SSO/OIDC)"]
    end

    UI --> API
    API --> CORE
    CORE --> ENGINES
    CORE --> STORE
    CORE --> CONN
    CONN --> EXT
    C5 --> S2
    S1 <--> C1
    X4 --> C5
    C8 --> X5
    A2 --> X6
```

---

## 2. C4 Diagram - Level 1 (Context)

```mermaid
flowchart TB
    DE["Detection Engineer"]
    SM["SOC Manager"]
    AN["SOC Analyst"]
    AU["Auditor"]

    DEP["<b>Detection Engineering Platform</b><br/>Catalog, documentation, implementations,<br/>validation, posture and reporting"]

    GIT["Git Server<br/>(GitHub/GitLab/Gitea)"]
    SEN["Microsoft Sentinel<br/>DEV + PROD"]
    QR["IBM QRadar<br/>PROD"]
    MITRE["MITRE ATT&CK<br/>STIX/TAXII"]
    IDP["Identity Provider<br/>OIDC/SAML"]
    SOAR["SOAR / ITSM"]

    DE --> DEP
    SM --> DEP
    AN --> DEP
    AU --> DEP

    DEP <--> GIT
    DEP <--> SEN
    DEP <--> QR
    DEP <-- "downloads catalog" --> MITRE
    DEP <--> IDP
    DEP --> SOAR
```

---

## 3. C4 Diagram - Level 2 (Containers)

```mermaid
flowchart TB
    subgraph DEPBOX["Detection Engineering Platform"]
        WEB["<b>Web UI</b><br/>React + TypeScript<br/>SPA"]
        APIC["<b>API</b><br/>FastAPI (Python)<br/>REST + OpenAPI"]
        WORKER["<b>Worker</b><br/>Celery / arq<br/>asynchronous tasks"]
        SCHED["<b>Scheduler</b><br/>internal cron<br/>periodic validations"]
        GITSVC["<b>Git Sync Service</b><br/>read/write repo,<br/>PRs, webhooks"]
        DB[("<b>PostgreSQL 16</b><br/>index, metrics,<br/>audit log")]
        REDIS[("<b>Redis</b><br/>queue + cache")]
        OBJ[("<b>MinIO / S3</b><br/>evidence")]
    end

    WEB -->|"HTTPS/JSON"| APIC
    APIC --> DB
    APIC --> REDIS
    APIC --> GITSVC
    APIC --> OBJ
    WORKER --> DB
    WORKER --> REDIS
    WORKER --> OBJ
    WORKER --> GITSVC
    SCHED --> REDIS
    GITSVC --> GITREPO[("Git Repository")]
    WORKER --> CONNS["Connectors"]
    CONNS --> SIEMS["Sentinel / QRadar / EDR"]
```

**Stack rationale (proposed, subject to review):**

| Component | Choice | Why |
|-----------|--------|-----|
| Backend | Python 3.12 + FastAPI | pySigma, SigmaForge and the detection ecosystem are Python |
| Model validation | Pydantic v2 | The same model serves the API, YAML and DB |
| ORM | SQLAlchemy 2 + Alembic | Controlled migrations |
| Queue | Celery or `arq` on Redis | Backtests and syncs are long-running |
| Frontend | React + TypeScript + TanStack Query | Mature ecosystem, complex tables |
| UI kit | shadcn/ui + Tailwind | Fast, consistent, open source |
| Query editor | Monaco Editor | KQL/AQL/YAML syntax highlighting |
| ATT&CK diagrams | ATT&CK Navigator layer export | De facto standard |
| Git | GitPython + provider API | Programmatic PRs |
| Auth | OIDC (Keycloak/Entra ID) | Corporate SSO |
| Deployment | Docker Compose (v0.1) → Helm (v1.0) | Operable by 1-3 people |

---

## 4. C4 Diagram - Level 3 (Detection Engine Components)

```mermaid
flowchart TB
    subgraph DE["Detection Engine"]
        direction TB

        subgraph CATALOG["Catalog Domain"]
            CA1["DetectionRepository"]
            CA2["IntentService"]
            CA3["TaxonomyService<br/>(MITRE, layers, data sources)"]
            CA4["DocumentationService"]
            CA5["VersioningService"]
        end

        subgraph IMPL["Implementation Domain"]
            IM1["ImplementationRepository"]
            IM2["LogicStore<br/>(KQL/AQL literal)"]
            IM3["SigmaAdapter"]
            IM4["TranslationOrchestrator<br/>→ SigmaForge"]
            IM5["LintService<br/>(KQL/AQL parsers)"]
            IM6["ExceptionService"]
        end

        subgraph VALID["Validation Domain"]
            VA1["TestRegistry"]
            VA2["ValidationOrchestrator"]
            VA3["DataAvailabilityValidator"]
            VA4["SchemaValidator"]
            VA5["BacktestRunner"]
            VA6["RSigmaAdapter"]
            VA7["EvidenceStore"]
            VA8["FindingsEngine"]
        end

        subgraph POSTURE["Posture Domain"]
            PO1["ScoringEngine"]
            PO2["CoverageCalculator"]
            PO3["HealthMonitor"]
            PO4["MetricsAggregator"]
            PO5["SnapshotService"]
            PO6["ReportGenerator"]
        end

        subgraph OPS["Operations Domain"]
            OP1["DeploymentService"]
            OP2["DriftDetector"]
            OP3["ConnectorRegistry"]
            OP4["SyncScheduler"]
            OP5["ApprovalWorkflow"]
            OP6["AuditLogger"]
        end
    end

    CA1 --> IM1
    IM3 --> IM4
    IM4 --> IM5
    VA2 --> VA3 & VA4 & VA5 & VA6
    VA5 --> OP3
    VA2 --> VA7
    VA2 --> VA8
    VA8 --> IM6
    PO1 --> PO2 & PO3 & PO4
    PO1 --> PO5
    OP2 --> OP3
    OP1 --> OP5
    OP1 --> OP6
```

---

## 5. Main data flow

```mermaid
sequenceDiagram
    autonumber
    actor DE as Detection Engineer
    participant UI as Web UI
    participant API as API
    participant GIT as Git Repo
    participant DB as PostgreSQL
    participant SF as SigmaForge
    participant CN as Sentinel Connector
    participant SEN as Sentinel

    DE->>UI: Creates DET-0003 (intent, MITRE, layers)
    UI->>API: POST /detections
    API->>DB: validates + persists draft
    API->>GIT: commit detection.yml + README.md (branch feature)
    GIT-->>API: commit sha

    DE->>UI: Adds Sentinel implementation (native KQL)
    UI->>API: POST /detections/DET-0003/implementations
    API->>SF: (optional) generate from Sigma
    SF-->>API: generated KQL
    API->>GIT: commit rule.kql
    API->>DB: indexes DetectionLogic + hash

    DE->>UI: Runs 10d backtest
    UI->>API: POST /validations {type: historical_backtest}
    API->>CN: run_query(kql, lookback=10d)
    CN->>SEN: Log Analytics query
    SEN-->>CN: results
    CN-->>API: 5 matches
    API->>DB: ValidationRun + metrics
    API->>GIT: commit validation record + evidence pointer
    API-->>UI: PASS · 5 matches
    DE->>UI: Marks 3 as noise
    UI->>API: POST /findings
    API->>DB: FND-0001 (noise)

    DE->>UI: Requests promotion to PROD
    UI->>API: POST /deployments
    API->>API: checks gates (findings, tests, approval)
    API->>CN: deploy(rule)
    CN->>SEN: create/update analytics rule
    SEN-->>CN: rule GUID
    CN-->>API: OK
    API->>DB: Deployment SUCCESS
    API->>GIT: merge to main + tag
```

---

## 6. The Data Collector and the Posture Engine

This is the piece that makes sure **the platform does not lie**.

```mermaid
flowchart TB
    subgraph SCHED["Scheduler (every N hours)"]
        T1["sync_inventory"]
        T2["sync_metrics"]
        T3["check_data_sources"]
        T4["detect_drift"]
        T5["recompute_posture"]
    end

    subgraph CONNECTORS["Connectors"]
        C1["Sentinel Connector"]
        C2["QRadar Connector"]
        C3["EDR Connector"]
        C4["Future Connector"]
    end

    subgraph COLLECT["Data Collector"]
        D1["Normalizer<br/>to DEP model"]
        D2["Reconciler<br/>Git and SIEM"]
        D3["Deduplicator"]
    end

    subgraph PE["Posture Engine"]
        P1["Coverage<br/>Calculator"]
        P2["Health<br/>Monitor"]
        P3["Quality<br/>Scorer"]
        P4["Effectiveness<br/>Analyzer"]
        P5["Governance<br/>Checker"]
        P6["Score<br/>Aggregator"]
    end

    T1 --> CONNECTORS
    T2 --> CONNECTORS
    T3 --> CONNECTORS
    CONNECTORS --> COLLECT
    COLLECT --> DB[("PostgreSQL")]
    T4 --> D2
    D2 --> FIND["Findings<br/>(drift)"]
    T5 --> PE
    DB --> PE
    PE --> SNAP[("PostureSnapshot")]
    SNAP --> DASH["Posture Dashboard"]
```

**What each connector collects:**

| Data collected | Sentinel | QRadar | Use |
|----------------|:--------:|:------:|-----|
| List of rules and their status (enabled/disabled) | Yes | Yes | Real inventory, drift |
| Literal query of each rule | Yes | Yes | Comparison with Git |
| Last modification and by whom | Yes | partial | Drift, audit |
| No. of alerts generated per rule | Yes | Yes | Effectiveness |
| Incidents closed as TP/FP | Yes | Yes | Precision |
| Available tables and volume | Yes | Yes | Data availability |
| Fields present in the tables | Yes | partial | Schema validation |
| Watchlists / reference sets | Yes | Yes | EnrichmentAsset staleness |
| Execution cost/time | Yes | partial | Performance |
| Rule execution errors | Yes | Yes | Health → `degraded` |

---

## 7. Deployment model

### 7.1 Development / MVP (v0.1)

```mermaid
flowchart LR
    subgraph HOST["A single host / VM"]
        direction TB
        DC["docker compose"]
        DC --> W["web:3000"]
        DC --> A["api:8000"]
        DC --> WK["worker"]
        DC --> PG[("postgres:5432")]
        DC --> RD[("redis:6379")]
        DC --> MO[("minio:9000")]
    end
    HOST -.->|"outbound HTTPS"| SIEM["Sentinel / QRadar APIs"]
    HOST -.->|"SSH/HTTPS"| GITR["Remote Git"]
```

### 7.2 Production (v1.0)

```mermaid
flowchart TB
    subgraph K8S["Kubernetes / OpenShift"]
        ING["Ingress + TLS"]
        ING --> WEBP["web (2 replicas)"]
        ING --> APIP["api (2-3 replicas)"]
        APIP --> PGP[("PostgreSQL HA<br/>+ backups")]
        APIP --> RDP[("Redis")]
        WKP["workers (n replicas)<br/>queues: sync, backtest, scoring"]
        WKP --> PGP
        WKP --> RDP
        WKP --> S3[("S3/MinIO<br/>evidence, WORM")]
        CJ["CronJobs<br/>sync / posture"]
    end
    K8S --> VAULT["Secret manager<br/>(SIEM credentials)"]
    K8S --> GITE["Enterprise Git"]
    K8S --> OBS["Observability<br/>Prometheus + Loki"]
```

---

## 8. Security architecture

```mermaid
flowchart TB
    subgraph AUTHZ["Access control"]
        SSO["OIDC / SAML"] --> RBAC["RBAC by role"]
        RBAC --> R1["viewer"]
        RBAC --> R2["analyst"]
        RBAC --> R3["engineer"]
        RBAC --> R4["approver"]
        RBAC --> R5["admin"]
        RBAC --> R6["auditor (read+export)"]
    end
```

| Resource / action | viewer | analyst | engineer | approver | admin | auditor |
|-------------------|:------:|:-------:|:--------:|:--------:|:-----:|:-------:|
| View catalog and documentation | Yes | Yes | Yes | Yes | Yes | Yes |
| View logic (KQL/AQL) | No | Yes | Yes | Yes | Yes | Yes |
| Create/edit detection | No | No | Yes | Yes | Yes | No |
| Run backtest in DEV | No | No | Yes | Yes | Yes | No |
| Run backtest in PROD | No | No | Limited | Yes | Yes | No |
| Deploy to DEV | No | No | Yes | Yes | Yes | No |
| Deploy to PROD | No | No | No | Yes | Yes | No |
| Create/close Findings | No | Yes | Yes | Yes | Yes | No |
| Accept risk (`accepted_risk`) | No | No | No | Yes | Yes | No |
| Manage connectors and credentials | No | No | No | No | Yes | No |
| Export audit reports | No | No | Yes | Yes | Yes | Yes |
| View full audit log | No | No | No | Yes | Yes | Yes |

**Additional controls:**

| Control | Implementation |
|---------|----------------|
| SIEM credentials | Never in Git or in the DB. Vault / K8s secrets / Managed Identity |
| Principle of least privilege | Read-only account for sync; separate account with write access only for deployment |
| Segregation of duties | The author of a change cannot approve it (rule in `ApprovalWorkflow`) |
| Evidence integrity | Mandatory sha256 + optional WORM storage |
| Audit log | Append-only table + signed export |
| Sensitive data in evidence | `redacted` flag + review before uploading log samples |
| Protection of the logic | Detection logic is sensitive information: RBAC + `visibility` + TLP |
| Secrets scanning in CI | Prevent a KQL containing an API key from ending up in the repo |
| Rate limiting toward the SIEM | Backtests can cost money (Log Analytics) → per-user quotas |

---

## 9. "Single GUI" view (decision D-05 formalized)

```mermaid
flowchart TB
    ENG["Detection Engineer"] --> GUI["<b>DEP Web UI</b><br/>the only interface"]

    GUI --> ACT1["Detections<br/>├── Search<br/>├── Create<br/>├── Edit<br/>├── Validate<br/>├── Test<br/>├── Deploy<br/>├── Compare<br/>└── Report"]

    ACT1 --> BE["Backend"]
    BE --> S["Sigma<br/><i>portable model</i>"]
    BE --> SFG["SigmaForge<br/><i>translation engine</i>"]
    BE --> RS["RSigma<br/><i>testing</i>"]
    BE --> VAL["Own validators"]
    BE --> CONN["Connectors"]

    SFG --> KQL["KQL"]
    SFG --> AQL["AQL"]
    CONN --> SEN["Sentinel"]
    CONN --> QRD["QRadar"]

    style GUI fill:#1a4d8f,color:#fff
    style SFG fill:#444,color:#fff
    style S fill:#444,color:#fff
    style RS fill:#444,color:#fff
```

> The engineer **never** thinks *"now I have to open SigmaForge"*.
> They click **Generate Implementation → Target: Microsoft Sentinel** and the platform
> runs SigmaForge behind the scenes.

---

## 10. Extensibility: plugin model

```mermaid
flowchart LR
    subgraph CORE["Core (stable)"]
        REG["Plugin Registry"]
        IFACE["Abstract<br/>interfaces"]
    end

    subgraph PLUGINS["Plugins (interchangeable)"]
        P1["Connector Plugin<br/>list_rules()<br/>get_rule()<br/>deploy_rule()<br/>run_query()<br/>get_metrics()"]
        P2["Translator Plugin<br/>translate(sigma, target)"]
        P3["Validator Plugin<br/>validate(detection, ctx)"]
        P4["Exporter Plugin<br/>export(scope, format)"]
        P5["Enricher Plugin<br/>enrich(detection)"]
    end

    REG --> P1 & P2 & P3 & P4 & P5
    IFACE -.-> P1 & P2 & P3 & P4 & P5
```

**Minimum contract of a Connector** (Python interface):

```python
class BaseConnector(Protocol):
    platform_id: str
    capabilities: set[Capability]   # {LIST, READ, DEPLOY, QUERY, METRICS, SCHEMA}

    def health_check(self) -> HealthStatus: ...
    def list_rules(self, env: Environment) -> list[RemoteRule]: ...
    def get_rule(self, env: Environment, native_id: str) -> RemoteRule: ...
    def deploy_rule(self, env: Environment, impl: Implementation,
                    dry_run: bool = False) -> DeploymentResult: ...
    def disable_rule(self, env: Environment, native_id: str) -> DeploymentResult: ...
    def run_query(self, env: Environment, query: str,
                  timespan: timedelta, limit: int) -> QueryResult: ...
    def list_tables(self, env: Environment) -> list[RemoteTable]: ...
    def describe_table(self, env: Environment, table: str) -> TableSchema: ...
    def get_rule_metrics(self, env: Environment, native_id: str,
                         period: DateRange) -> RuleMetrics: ...
    def list_enrichment_assets(self, env: Environment) -> list[RemoteAsset]: ...
```

A connector can declare partial capabilities. E.g., `QRadar` can declare
`{LIST, READ, QUERY, METRICS}` without `DEPLOY` if it is decided not to automate legacy deployments.
The UI **disables** unsupported actions instead of failing.

---

## 11. Git <-> Database strategy

```mermaid
flowchart LR
    subgraph GIT["Git - SOURCE OF TRUTH"]
        G1["detection.yml"]
        G2["*.md"]
        G3["*.kql / *.aql"]
        G4["tests/"]
        G5["validations/*.yml"]
        G6["findings/*.yml"]
    end

    subgraph DB["PostgreSQL - DERIVED INDEX"]
        D1["Normalized tables"]
        D2["Full-text search"]
        D3["Metric series"]
        D4["Audit log"]
        D5["Scoring caches"]
    end

    GIT -->|"git sync<br/>(webhook or poll)"| DB
    DB -->|"write via UI →<br/>commit + PR"| GIT

    NOTE["[WARN] The DB can be deleted<br/>and rebuilt from Git<br/>at any time.<br/>Exceptions: metrics and audit log,<br/>which are append-only and backed up separately."]
```

| Data | Lives in Git | Lives in DB | Rebuildable |
|------|:------------:|:-----------:|:-----------:|
| Detection metadata (`detection.yml`) | Yes | index | Yes |
| Markdown documentation | Yes | FTS index | Yes |
| KQL/AQL logic | Yes | index | Yes |
| Canonical Sigma | Yes | index | Yes |
| Test definitions | Yes | index | Yes |
| ValidationRun records | Yes (YAML) | Yes | Yes |
| Findings | Yes (YAML) | Yes | Yes |
| Evidence (binaries) | pointer + hash | metadata | Warning: requires object storage |
| Time-series metrics | No | Yes | No (own backup) |
| Audit log | No | Yes | No (own backup) |
| PostureSnapshots | No (or periodic export) | Yes | recomputable |

---

## 12. Operational requirements

| Aspect | Definition |
|--------|------------|
| **Backup** | Daily PostgreSQL + remote Git + replicated object storage |
| **RTO / RPO** | RTO 4h / RPO 24h (not a real-time system) |
| **Observability** | Prometheus metrics, structured JSON logs, OpenTelemetry traces |
| **Health endpoints** | `/healthz`, `/readyz`, `/metrics` |
| **Operational alerts** | Connector down, failed sync, stuck queue, posture not computed in 48h |
| **ATT&CK update** | Monthly job that downloads the STIX bundle and flags obsolete mappings |
| **Retention** | Metrics 24 months, evidence per policy (default 24 months), audit log 7 years |
| **Languages** | UI in `es` and `en`; documentation in the language the team decides |
