# 14 - Decisions, Risks, Open Questions and Glossary

---

## 1. Architecture Decision Records (ADR)

Format: context → decision → consequences → rejected alternatives.

---

### ADR-001 - The root entity is `Detection`, not "rule"

**Context.** Today the Sentinel KQL and the QRadar AQL that detect the same
behavior are treated as two independent rules, with no formal relationship.

**Decision.** The root entity of the model is `Detection`, which represents **the behavior
we want to detect**. An `Implementation` represents **how we manage to detect it on
a specific technology**.

**Consequences.**
- [OK] The AQL and KQL of `DET-0003` are two implementations, not two rules.
- [OK] MITRE coverage is calculated once per behavior, not per technology.
- [OK] We can migrate SIEMs without losing the history of the detection.
- [WARN] Requires reconciliation work during import.
- [WARN] Forces us to define the `intent`, which today is not written anywhere.

**Rejected alternatives.**
- *One rule = one entity*: simple, but reproduces exactly the current problem.
- *Group by tags*: informal, does not allow validation or reliable coverage.

---

### ADR-002 - Four layers: Intent / Implementation / Validation / Posture

**Context.** A `detection.yml` that mixes everything becomes a giant, unmanageable Sigma
and does not allow reasoning about quality.

**Decision.** The model is organized into four explicit layers, each answering a
different question.

**Consequences.**
- [OK] Each layer evolves separately.
- [OK] We can have intent without implementation (declared gap) or implementation without
  validation (visible debt).
- [OK] It is what lets us get close to the CardinalOps proposal while being open source.
- [WARN] More entities to manage.

---

### ADR-003 - Git is the source of truth; PostgreSQL is an index

**Context.** We need history, peer review, rollback and audit.

**Decision.** All canonical content lives in Git. The database indexes for
search, scoring and time series, and can be rebuilt.

**Consequences.**
- [OK] PR review, full history, trivial rollback.
- [OK] The repo outlives the platform.
- [WARN] Every write from the UI implies a commit → latency and complexity.
- [WARN] Metrics and the audit log are **not** reconstructible: they require their own backup.

**Rejected alternative.** *DB as source of truth with export to Git*: loses
peer review and makes the audit dependent on the platform.

---

### ADR-004 - A single GUI; Sigma/SigmaForge/RSigma are backend

**Context.** There is a temptation to use SigmaForge as the interface for the
translation part.

**Decision.** We do not build a second platform. SigmaForge is an internal component
invoked from our GUI.

**Consequences.**
- [OK] The engineer works in a single place.
- [OK] We can replace SigmaForge with another translator without changing the experience.
- [WARN] We have to maintain an adapter and follow the evolution of SigmaForge.

---

### ADR-005 - Three implementation types, and `native` is first-class

**Context.** Real rules use `binary_and()`, `summarize`, `make_set()`,
`_GetWatchlist()`. Forcing them through Sigma would lose Sentinel features.

**Decision.** `generated`, `generated_customized` and `native`. None is inferior.
The actual KQL/AQL is preserved verbatim **always**.

**Consequences.**
- [OK] Nothing is lost in the migration.
- [OK] The real portability of the catalog can be measured as a deliberate metric.
- [WARN] `native` detections do not get automatic testing via RSigma; they need
  their own unit tests.

---

### ADR-006 - The environment is a dimension of the implementation  
> **Status: Superseded by ADR-013.** Kept as history.

**Context.** The initial draft modeled `environments: [dev, prod]` as a list
inside the Sentinel implementation.

**Decision.** Each platform+environment combination is an independent `Implementation`,
with its own version, hash, state and validations.

**Consequences.**
- [OK] It is the only thing that allows representing "DEV v1.4 vs PROD v1.2".
- [OK] Enables environment drift and the promotion flow.
- [WARN] More entries in `implementations[]`. Mitigated with inheritance: DEV can declare
  `inherits_from` to avoid duplicating configuration.

---

### ADR-007 - Validation is an entity, not a field

**Context.** `last_tested: 2026-08-26` does not say what was tested or what happened.

**Decision.** `Test` (definition) + `ValidationRun` (execution) + `Evidence` + `Finding`.

**Consequences.**
- [OK] Real audit: which version, with what data, who, with what evidence.
- [OK] Findings outlive the test and block promotions.
- [WARN] More files per detection. Mitigated with `validations/index.yml`.

---

### ADR-008 - MITRE coverage against a threat profile, not against all of ATT&CK

**Context.** Reporting "23% ATT&CK coverage" is a demoralizing number and not
actionable.

**Decision.** The denominator is a documented and approved threat profile. Total
coverage is also reported as context, always in the background.

**Consequences.**
- [OK] Actionable coverage, with prioritized gaps.
- [OK] Accepted gaps are justified in writing (useful in audits).
- [WARN] The profile has to be defined and maintained: it is real work, not automatic.

---

### ADR-009 - Detection metrics and program metrics are never mixed

**Context.** Mixing them produces dashboards that serve no one.

**Decision.** `Metric.scope` separates both families. The UI presents them on
different screens.

---

### ADR-010 - The platform does not lie

**Context.** It is easy to build a green dashboard with stale data.

**Decision.** If a connector is down, the UI shows the age of the data. If there is no
validation, the score is penalized with a `cap`. If drift is unknown, it says
`unknown`, not `in_sync`.

**Consequences.**
- [OK] Long-term trust.
- [WARN] The first dashboards will look worse than expected. **This is correct**: it reflects
  the current reality, which is exactly the problem the project wants to solve.

---

### ADR-011 - The detection ID is immutable and never reused

**Decision.** `DET-0001` identifies that detection forever, even if retired.

**Consequences.** Allows answering an auditor about the past. Prevents confusion in
old tickets and historical evidence.

---

### ADR-013 - The environment is determined by the branch

**Context.** ADR-006 modeled each platform+environment combination as an `Implementation`
with `environment` in the YAML. That contradicts the GitOps flow of `docs/05 §5`
(`develop` = DEV, `main` = PROD, promotion by PR): on merge, a file with
`environment: dev` would carry that value into production.

**Decision.**
- `implementations[].environment` is removed from the schema. One implementation per platform:
  `implementations/<plataforma>/rule.<ext>`; the ID does not encode the environment (`IMP-0003-SENTINEL`).
- `.dep/environments.yml` maps `branch → environment`; environments are defined in
  `taxonomy/environments.yml` (which keeps `tier` and `requires_approval`).
- A branch with an environment that has `requires_approval: true` is *protected*: `dep commit` refuses to
  commit directly to it (override `--allow-protected`). Real protection is
  configured on the Git host.

**Consequences.**
- [OK] Promotion is a merge with no content changes; DEV<->PROD drift is `git diff develop..main`.
- [OK] Less duplication: per-environment folders and entries disappear.
- [WARN] Breaking schema change: existing repos must migrate (`DEP-ENV-004` guides the process).
- [WARN] Legitimate per-environment differences (workspace, scheduling) no longer fit in the
  detection; they will live in environment configuration (deployment slice).
- [WARN] `inherits_from` loses its main motivation (DEV/PROD pairs).
- Note: `docs/02-data-model.md` describes the platform model (not implemented in this repository yet)
  and still reflects ADR-006; it will be aligned when that branch is resumed.

---

### ADR-012 - Segregation of duties in production

**Decision.** The author of a change cannot approve it. Enforced both by `CODEOWNERS`
and by the platform's `ApprovalWorkflow`.

**Consequences.** Requires at least 2 people with permissions. In single-person
teams, a documented exception must be explicitly declared.

---

## 2. Risk register

| ID | Risk | Prob. | Impact | Mitigation | Owner |
|----|--------|:-----:|:-------:|------------|-------|
| R-01 | SIEM APIs do not expose what is needed | medium | high | Week 1 spikes; degrade connector capabilities | Platform |
| R-02 | Migration is abandoned halfway | medium | high | Short waves; v0.1 useful from the start | Lead |
| R-03 | Intent is never filled in → catalog without value | high | high | Lifecycle gate; pair sessions | Lead |
| R-04 | Cost of backtests in Log Analytics | high | medium | Cost guard, quotas, limited lookback | Platform |
| R-05 | Bus factor 1 | high | high | This documentation; standard stack | Everyone |
| R-06 | Scoring loses credibility due to odd numbers | medium | high | Caps, calibration with the 10, review with the team | Lead |
| R-07 | SigmaForge changes its API or is abandoned | medium | medium | Isolated adapter; `native` as plan B | Dev |
| R-08 | Evidence containing personal data | medium | high | Redaction by default, `redacted` flag, retention | Lead |
| R-09 | The platform writes something incorrect to PROD | low | critical | Mandatory dry-run, approval, rollback, QRadar without DEPLOY | Platform |
| R-10 | SIEM credentials exposed | low | critical | Secret manager, separate accounts, no secrets in Git | Platform |
| R-11 | The repo grows too large due to evidence | medium | low | LFS / object storage, retention policy | Platform |
| R-12 | False drift due to SIEM reformatting | high | medium | Documented normalization before comparing | Dev |
| R-13 | Team resistance ("yet another tool") | medium | high | It must replace the scattered notes from day 1, not add to them | Lead |
| R-14 | Sentinel<->QRadar reconciliation merges distinct detections | medium | high | Never automatic; mandatory human review | Dev |
| R-15 | ATT&CK changes and breaks the mappings | high | low | Declared ATT&CK version; monthly job that flags obsolete ones | Dev |

---

## 3. Open questions

| # | Question | Who decides | When | Blocks |
|---|----------|--------------|--------|:-------:|
| Q-01 | Where is the `DET-ID` stored inside a Sentinel rule? (description, tag, template name) | Platform | Week 1 spike | Connector |
| Q-02 | Do we grant the `DEPLOY` capability to the QRadar connector? | SOC Lead | Before v0.2 | Connector |
| Q-03 | Which mapping of QRadar/Sentinel "closing reasons" counts as TP and as FP? | SOC Lead | Before v0.3 | Effectiveness |
| Q-04 | What is the corporate threat profile? (coverage denominator) | SOC Lead + TI | Before v0.3 | Coverage |
| Q-05 | Evidence retention? (24 months proposed) | Compliance | Before v0.1 | Storage |
| Q-06 | Is PROD evidence anonymized? (proposed: yes, by default) | Compliance | Before v0.2 | Backtest |
| Q-07 | Who is `approver` if the team is a single person? | SOC Lead | Before v0.2 | Workflow |
| Q-08 | Review cadence by severity? (proposed 90/120/180/365) | SOC Lead | Before v0.1 | Governance |
| Q-09 | Multi-tenant in the future? (`tenant_id` is reserved just in case) | Product | v1.0+ | Schema |
| Q-10 | Final product name? | Everyone | Whenever we feel like it | Nothing |
| Q-11 | Is it published as open source? Under which license? | Management | Before v1.0 | Legal |
| Q-12 | Language of the detection documentation: `es` or `en`? | SOC Lead | Before the migration | Migration |
| Q-13 | Are Content Hub rules documented the same way as our own? | SOC Lead | Wave 3 | Migration |
| Q-14 | Do we integrate with the existing SOAR or postpone it? | SOC Lead | v0.3 | TP/FP metrics |

> **Q-12 deserves attention:** the language must be decided **before** migrating, because changing
> hundreds of documents afterwards is costly. Recommendation: technical documentation in English
> (aligned with MITRE, Sigma and the community), interface and internal communication in Spanish.

---

## 4. Glossary

| Term | Definition in this project |
|---------|------------------------------|
| **Detection** | The adversary behavior we want to detect. Technology-independent. Root entity. |
| **Implementation** | How that behavior is detected on a specific platform and environment (a KQL in Sentinel PROD). |
| **Intent** | The formalization of the "what": behavior, hypothesis, scope, assumptions. |
| **Detection Logic** | The literal query (KQL, AQL, Sigma), preserved without transformation. |
| **Environment** | Instance of a platform: `Sentinel DEV`, `Sentinel PROD`, `QRadar PROD`. |
| **Detection Layer** | Visibility layer: identity, endpoint, network, cloud, email… |
| **Data Source** | Logical data source (`windows-security-events`). |
| **Log Source** | Materialization of a data source on a platform (`SecurityEvent` in Sentinel). |
| **Schema Field** | A specific field of a log source, with its measured reliability. |
| **Test** | Reusable definition of a test (given/when/then). |
| **Validation Run** | A concrete execution of a validation, with date, dataset, result and evidence. |
| **Finding** | Persistent finding produced by a validation or by the system. |
| **Evidence** | Artifact that proves what happened, with mandatory sha256. |
| **Exception Rule** | Exclusion or adjustment applied to an implementation, with justification and accepted risk. |
| **Enrichment Asset** | Watchlist, lookup or reference set an implementation depends on. |
| **Deployment** | Action of taking an implementation to an environment, with its approval. |
| **Drift** | Divergence. Three types: deployment (Git<->SIEM), environment (DEV<->PROD), translation (Sigma<->logic). |
| **Orphan Rule** | A rule active in a SIEM that does not exist in the catalog. |
| **Posture** | State of quality and maturity, at detection or program level. |
| **Detection Score** | A 0-100 score for a detection, across 7 dimensions. |
| **Posture Snapshot** | Snapshot of the program state at a given moment. |
| **Coverage Item** | Coverage element (a technique, a source, a layer) with its status. |
| **Threat Profile** | Set of techniques relevant to the organization. Denominator of coverage. |
| **Gap** | Element of the threat profile without sufficient coverage. Can be accepted and justified. |
| **Promotion Gate** | Condition that must be met to deploy to production. |
| **Sigma** | Portable detection rule language. Here: optional canonical model. |
| **SigmaForge** | Sigma → KQL/AQL translation engine. Here: backend component. |
| **RSigma** | Rule testing framework. Here: one of the validation runners. |
| **Native implementation** | Implementation written directly in the SIEM language, without going through Sigma. |
| **Generated / Customized** | Implementation produced by translation, with or without later editing. |
| **DEP** | Detection Engineering Platform. Working name of the project. |

---

## 5. References and relevant prior work

| Resource | Relevance |
|---------|------------|
| MITRE ATT&CK | Technique taxonomy; basis of coverage |
| MITRE DeTT&CT | `coverage_level` scale and data source quality model |
| Sigma / pySigma | Portable detection model |
| SigmaForge | Translation engine |
| Atomic Red Team | Atomic tests for validation |
| Detection Engineering Maturity Matrix (Kyle Bailey) | Program maturity reference |
| "Detection as Code" (various authors) | Git, CI and versioning practices applied to detection |
| Palantir ADS Framework (Alerting and Detection Strategy) | Detection documentation structure (goal, categorization, strategy abstract, technical context, blind spots, FP, validation, priority, response) |
| CardinalOps | Commercial posture management reference; functional target to match |
| ATT&CK Navigator | Coverage export format |

> **Note on the Palantir ADS Framework:** its structure (especially *blind spots*
> and *strategy abstract*) is incorporated into our model as `intent.evasion_notes`,
> `intent.scope.excluded` and `intent.hypothesis`. It is a good cross-check to verify that the
> documentation of a detection is complete.

---

## 6. How to keep this documentation alive

| Document | When it is updated | Who |
|-----------|---------------------|-------|
| 02 Data model | Every time an entity or attribute is added | Dev + Lead |
| 04 YAML schema | Every `schema_version` change | Dev |
| 07 Scoring | Every recalibration of weights or formulas | Lead |
| 13 Roadmap | When each milestone closes | Lead |
| 14 ADR | Every new structural decision | Whoever decides |
| Rest | When reality diverges | Everyone |

**Rule:** an ADR is never deleted or edited. If a decision changes, a new ADR is written
that **supersedes** the previous one, and the previous one is marked `Superseded by ADR-XXX`.
Just as with detections: history is not rewritten.
