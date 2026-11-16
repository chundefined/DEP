# 08 - Lifecycle and Operational Workflows

---

## 1. Complete lifecycle of a detection

```mermaid
stateDiagram-v2
    direction TB
    [*] --> idea : gap identified
    idea --> draft : intent + MITRE documented
    draft --> in_development : logic is written
    in_development --> in_review : PR opened
    in_review --> in_development : changes requested
    in_review --> testing : approved
    testing --> in_development : tests fail
    testing --> production_candidate : gates passed
    production_candidate --> tuning : blocking findings
    tuning --> production_candidate : findings resolved
    production_candidate --> active : deployed + validated in PROD
    active --> tuning : new finding
    active --> degraded : missing data / drift / errors
    degraded --> active : recovered
    degraded --> tuning
    active --> disabled : temporary deactivation
    disabled --> active
    active --> deprecated : replaced or obsolete
    degraded --> deprecated
    disabled --> deprecated
    deprecated --> retired : removed from all environments
    retired --> [*]
```

### Transitions: who can perform them and what is required

| Transition | Role | Preconditions | Effects |
|------------|------|---------------|---------|
| `idea → draft` | engineer | Intent + ≥1 MITRE mapping | Folder and `detection.yml` are created |
| `draft → in_development` | engineer | Data sources declared | - |
| `in_development → in_review` | engineer | Logic present, `syntax_validation` PASS | Opens PR |
| `in_review → testing` | reviewer | 1 approval | Merge to `develop`, deploy to DEV |
| `testing → production_candidate` | engineer | Gates from `.dep/policies.yml` | - |
| `production_candidate → active` | approver | PROD deployment success + `deployment_validation` | Tag, audit event |
| `active → tuning` | system/engineer | Open finding with severity ≥ medium | Notification to the owner |
| `active → degraded` | system | F-01/F-04/F-05/F-06 | Operational alert, score cap |
| `active → disabled` | approver | Mandatory justification | Rule disabled in the SIEM |
| `* → deprecated` | approver + owner | `deprecation.reason` + `replaced_by` (or a justification for no replacement) | Marked; not deleted |
| `deprecated → retired` | approver | All deployed implementations removed or disabled | Archived; the `DET-` ID is never reused |

---

## 2. Lifecycle of an implementation

```mermaid
stateDiagram-v2
    [*] --> draft
    draft --> not_deployed : logic ready
    not_deployed --> active : deployment success
    active --> failed : execution error in the SIEM
    failed --> active : fixed
    active --> disabled : disabled in the SIEM
    disabled --> active
    active --> legacy : replaced by another platform
    legacy --> deprecated
    active --> deprecated
    deprecated --> [*] : removed from the SIEM
```

> `legacy` is the state of the QRadar implementation of `DET-0003`:
> it is still active and detecting, but it is not touched because the operational
> source of truth has moved to Sentinel.

---

## 3. Workflow: create a detection from scratch

```mermaid
flowchart TB
    A["1. Identify need<br/>(MITRE gap, TI, incident, request)"] --> B["2. Create Detection<br/>id, name, intent, MITRE, layers"]
    B --> C["3. Declare data sources<br/>and required fields"]
    C --> D{"4. Is there a reusable<br/>Sigma rule?"}
    D -- "yes" --> E["Import Sigma<br/>→ type: generated"]
    D -- "no" --> F{"Can it be expressed<br/>in Sigma?"}
    F -- "yes" --> G["Write Sigma<br/>→ SigmaForge → KQL"]
    F -- "no" --> H["Write native KQL<br/>→ type: native"]
    E --> I["5. Review / adjust<br/>→ generated_customized if edited"]
    G --> I
    H --> I
    I --> J["6. data_availability<br/>+ schema_validation"]
    J --> K{"Data OK?"}
    K -- "no" --> L["[BLOCKED] Finding: data_gap<br/>Escalate to ingestion"]
    K -- "yes" --> M["7. Unit tests<br/>(positive + negative)"]
    M --> N["8. Deploy to DEV"]
    N --> O["9. Historical backtest"]
    O --> P{"FP ratio > 0.3?"}
    P -- "yes" --> Q["10. Noise analysis<br/>→ Finding → Exception"]
    Q --> R["11. Tuning validation"]
    R --> O
    P -- "no" --> S["12. Document<br/>investigation + FP + response"]
    S --> T["13. PR to main<br/>+ approval"]
    T --> U{"14. Promotion gates"}
    U -- "fail" --> V["[BLOCKED] Blocked with reason"]
    U -- "pass" --> W["15. Deploy to PROD"]
    W --> X["16. deployment_validation"]
    X --> Y["17. status: active"]
    Y --> Z["18. Continuous monitoring"]
```

---

## 4. Workflow: QRadar → Sentinel migration

This is **the real DET-0001 flow**, now formalized and repeatable.

```mermaid
flowchart TB
    A["Existing QRadar rule"] --> B["1. Create/identify DET-XXXX"]
    B --> C["2. Register AQL as<br/>IMP-XXXX-QRADAR-PROD<br/>status: legacy"]
    C --> D["3. Extract the intent<br/>from the AQL logic"]
    D --> E["4. Write equivalent KQL<br/>IMP-XXXX-SENTINEL-DEV"]
    E --> F["5. data_availability<br/>do the logs exist in Sentinel?"]
    F --> G["6. schema_validation<br/>are the fields equivalent?"]
    G --> H{"Fields<br/>reliable?"}
    H -- "no" --> I["Schema finding<br/>e.g.: AccountName unreliable in 4768/4771<br/>→ use TargetUserName"]
    I --> E
    H -- "yes" --> J["7. historical_backtest<br/>lookback 10d"]
    J --> K["8. Cross comparison<br/>do QRadar and Sentinel detect the same?"]
    K --> L{"Do they match?"}
    L -- "no" --> M["Analyze divergence:<br/>missing logic? different data?"]
    M --> E
    L -- "yes" --> N["9. noise_analysis"]
    N --> O["10. Tuning + exclusions"]
    O --> P["11. production_candidate"]
    P --> Q["12. Deploy PROD Sentinel"]
    Q --> R["13. Coexistence period<br/>(both active, compare)"]
    R --> S{"Sentinel ≥ QRadar<br/>for N weeks?"}
    S -- "no" --> O
    S -- "yes" --> T["14. QRadar → deprecated"]
    T --> U["15. QRadar → retired"]
```

**Key design point:** step 13 (coexistence) requires the model to support
**two simultaneously active implementations on different platforms** - which is exactly
what decision D-02 enables.

---

## 5. Workflow: DEV → PROD promotion

```mermaid
sequenceDiagram
    autonumber
    actor DE as Engineer
    participant UI
    participant GATE as Gate Engine
    participant AP as Approver
    participant CN as Connector
    participant SEN as Sentinel PROD
    participant GIT

    DE->>UI: Promote DET-0001 DEV → PROD
    UI->>GATE: evaluate(DET-0001, target=prod)
    GATE->>GATE: Required validations present and < 30d?
    GATE->>GATE: Open blocking findings?
    GATE->>GATE: Owner and approver defined?
    GATE->>GATE: Documentation complete?
    GATE->>GATE: Tests pass?
    alt any gate fails
        GATE-->>UI: [FAIL] BLOCKED + list of reasons
        UI-->>DE: shows checklist with what is missing
    else all OK
        GATE-->>UI: [OK] READY
        UI->>UI: shows diff DEV vs current PROD
        DE->>UI: requests approval
        UI->>AP: notification
        AP->>UI: reviews diff + evidence
        AP->>UI: approves
        UI->>CN: deploy(dry_run=true)
        CN-->>UI: change plan
        UI->>CN: deploy(dry_run=false)
        CN->>SEN: create/update rule
        SEN-->>CN: rule id + state
        CN-->>UI: SUCCESS
        UI->>CN: verify(rule) → deployment_validation
        CN-->>UI: hash matches [OK]
        UI->>GIT: merge + tag DET-0001@1.3.0
        UI->>UI: audit event + status → active
    end
```

### Gates checklist (visible in the UI)

```
Promotion gates - DET-0001 → Sentinel PROD

[OK]    Syntax validation             passed 2026-08-28
[OK]    Data availability             passed 2026-08-26
[OK]    Schema validation             passed 2026-08-26
[OK]    Historical backtest           passed 2026-08-26  (2 days ago, limit 30)
[FAIL]  Blocking findings             1 open: FND-0001 (noise, medium)
[OK]    Owner assigned                detection-engineering
[OK]    Approver assigned             soc-lead
[OK]    Documentation complete        4/4 required sections
[OK]    Unit tests                    3/3 passed
[WARN]  Approver ≠ author             pending selection

[BLOCKED] PROMOTION BLOCKED - resolve FND-0001 first
```

---

## 6. Workflow: drift detection

```mermaid
flowchart TB
    A["Job every 4h"] --> B["Connector: list_rules(env)"]
    B --> C["For each Implementation in Git"]
    C --> D{"Does it exist in the SIEM?"}
    D -- "no" --> E["drift: not_deployed<br/>Finding if status=active"]
    D -- "yes" --> F["Normalize remote query"]
    F --> G["hash_remote vs hash_git"]
    G --> H{"Do they match?"}
    H -- "yes" --> I["Compare enabled<br/>and schedule"]
    H -- "no" --> J["Compare timestamps"]
    J --> K{"Which is more<br/>recent?"}
    K -- "Git" --> L["drift: local_ahead<br/>→ pending deployment"]
    K -- "SIEM" --> M["drift: remote_ahead<br/>[WARN] someone edited in the console"]
    K -- "both changed" --> N["drift: diverged<br/>[WARN] requires manual reconciliation"]
    I --> O{"Does enabled match?"}
    O -- "yes" --> P["drift: in_sync [OK]"]
    O -- "no" --> Q["drift: config mismatch"]
    L & M & N & Q & E --> R["Create/update drift-type Finding"]
    R --> S["Notify owner"]
```

**Normalization before comparing** (to avoid generating false drift):

| Ignored | Reason |
|---------|--------|
| Leading/trailing whitespace on a line | The SIEM reformats |
| `\r\n` vs `\n` line breaks | Platform differences |
| Comments (optional, configurable) | Noise |
| Order of JSON properties in metadata | Not semantic |

| NOT ignored | Reason |
|-------------|--------|
| Changes inside strings | They could be exclusions |
| Clause order | It may change the result |
| Numeric values (thresholds) | Semantic |

### Drift screen

```
[WARN]  Kerberos BF - DRIFT DETECTED

              Git (main)        Sentinel PROD      Sentinel DEV
─────────────────────────────────────────────────────────────────
Version       1.4.0             1.2.0              1.4.0
Hash          8f2a1c…           c93b44…            8f2a1c…
Enabled       true              true               true
Modified      2026-08-28        2026-07-14         2026-08-28
Modified by   j.perez           unknown (console)  j.perez
Status        -                 remote_ahead [WARN] in_sync [OK]

Diff PROD vs Git:
  - | where TargetUserName != "NOUSER"
  + | where TargetUserName !in ("NOUSER", "HEALTHCHECK")

[WARN]  Someone edited this rule directly in the Sentinel console on 2026-07-14.
        The change is NOT in Git.

Recommendation:
  ▸ Adopt remote change into Git  (creates a PR with the diff)
  ▸ Overwrite remote with Git     (redeploys 1.4.0)
  ▸ Mark as accepted divergence   (requires justification)
```

---

## 7. Workflow: managing a Finding

```mermaid
flowchart TB
    A["Finding created<br/>(auto or manual)"] --> B{"blocks_promotion?"}
    B -- "yes" --> C["[BLOCKED] PROD gate blocked"]
    B -- "no" --> D["Enters backlog"]
    C --> D
    D --> E["Assignment to the owner"]
    E --> F{"Type"}
    F -- "noise" --> G["Analyze pattern<br/>→ propose ExceptionRule"]
    F -- "schema" --> H["Change the field used<br/>or escalate to ingestion"]
    F -- "data_gap" --> I["Escalate to the platform team"]
    F -- "drift" --> J["Reconcile Git with SIEM"]
    F -- "governance" --> K["Assign owner / review"]
    F -- "evasion" --> L["New detection or extend coverage"]
    G --> M["Apply change + tuning_validation"]
    H --> M
    J --> M
    L --> M
    M --> N{"Resolved?"}
    N -- "yes" --> O["status: resolved<br/>+ resolution_ref"]
    N -- "no, accepted" --> P["accepted_risk<br/>requires approver + expiry"]
    I --> Q["Blocked by third parties<br/>status: acknowledged"]
    O --> R["Unblocks gate"]
    P --> R
    P -.-> S["On expiry → back to open"]
```

---

## 8. Workflow: periodic review

```mermaid
flowchart LR
    A["Daily job"] --> B["next_review_due < today?"]
    B --> C["Create review task"]
    C --> D["Notify owner"]
    D --> E["Review checklist"]
    E --> F1["Is the intent still valid?"]
    E --> F2["Is the threat still active?"]
    E --> F3["Are the data sources still arriving?"]
    E --> F4["Is the precision acceptable?"]
    E --> F5["Are there new techniques that evade it?"]
    E --> F6["Are the exceptions still justified?"]
    E --> F7["Is the documentation correct?"]
    F1 & F2 & F3 & F4 & F5 & F6 & F7 --> G{"Decision"}
    G --> H["Keep unchanged<br/>→ next_review += cadence"]
    G --> I["Improve → new cycle"]
    G --> J["Deprecate"]
```

---

## 9. Workflow: retiring a detection

```mermaid
flowchart TB
    A["Retirement proposal"] --> B["Mandatory reason"]
    B --> C{"Category"}
    C -- "replaced" --> D["Declare replaced_by: DET-XXXX"]
    C -- "obsolete threat" --> E["Justification + TI reference"]
    C -- "permanently without data" --> F["Justification + accepted gap"]
    C -- "duplicate" --> G["Declare relationship duplicates"]
    D & E & F & G --> H["Approval (approver)"]
    H --> I["status: deprecated<br/>+ notice in the UI"]
    I --> J["Grace period<br/>(default 30 days)"]
    J --> K["Disable in all environments"]
    K --> L["deployment_validation<br/>is it really deactivated?"]
    L --> M["status: retired"]
    M --> N["Kept in the repo<br/>and in the posture history"]
    M --> O["[WARN] If it was the sole coverage of a technique:<br/>a CoverageItem with is_gap=true is generated"]
```

> **It is never deleted.** A retired detection stays in Git and in the history.
> The ID is never reused. This makes it possible to answer an auditor:
> *"what were you detecting in June 2025?"*

---

## 10. Inventory matrix (the view that makes everything evident)

```
Detection Inventory

                        SENTINEL          QRADAR      EDR    Health
                      DEV      PROD        PROD
────────────────────────────────────────────────────────────────────
Coerced Auth          ok       ok          ok         -      ● 92
Kerberos BF           ok       [WARN] drift ok        -      ◐ 74
Password Spray        ok       ok          -          -      ● 88
MFA Fatigue           ok       ok          -          -      ● 91
Golden Ticket         ok       -           ok         -      ◐ 61
LSASS Access          -        -           -          ok     ● 85
DNS Tunneling         ok       x disabled  -          -      ○ 38

Legend  ok active   [WARN] drift   x disabled   - not implemented
        ● healthy  ◐ degraded  ○ critical
```

Clicking on `[WARN] Kerberos BF`:

```
[WARN]  Kerberos BF - Environment inconsistency

DEV                    PROD                   QRadar
version 1.4.0          version 1.2.0          legacy implementation
hash 8f2a1c…           hash c93b44…           hash 55ee01…
enabled                enabled                enabled
validated 2026-08-28   validated 2026-06-02   validated 2025-11-10

Delta DEV → PROD:
  • Exclusion for loopback NOUSER (FND-0001) not present in PROD
  • Threshold changed from 3 to 5 failures

Recommendation:
  ▸ Promote DEV → PROD  (blocked: FND-0001 must be resolved first)
```

---

## 11. Notifications and events

| Event | Recipient | Channel | Priority |
|-------|-----------|---------|:--------:|
| Critical finding created | Owner + SOC lead | Email + Teams/Slack | high |
| Data source missing | Owner + Platform | Email + operational alert | high |
| `diverged` drift detected | Owner + Platform | Teams/Slack | high |
| Failed deployment to PROD | Author + Platform | Email | high |
| Pending approval | Approver | Teams/Slack | medium |
| Overdue periodic review | Owner | Weekly email | low |
| Exception about to expire (15d) | Owner + Approver | Email | medium |
| Monthly posture available | SOC Manager | Email with PDF | low |
| Detection with no alerts in 90d | Owner | Weekly email | low |
| New ATT&CK version | Detection team | Email | low |

All events are also emitted as **webhooks** (see doc 11) for integration with
SOAR/ITSM.
