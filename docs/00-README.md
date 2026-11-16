# Detection Engineering Platform (DEP)

> **Project master document.**
> Document version: `0.1.0` - Status: `Draft for review`
> This set of documents consolidates and formalizes everything agreed so far,
> and fills in the gaps that were missing before moving on to development.

---

## 0. What this is

DEP is an open source and extensible **Detection Engineering platform**, whose goal is to
replace the current model - documentation in loose notes + rules scattered across Sentinel and QRadar -
with a **single versioned source of truth in Git**, with a **single GUI**, able to answer
four questions at any time:

| Layer | Question it answers |
|------|-----------------------|
| **Intent** | What behavior do I want to detect? |
| **Implementation** | How do I detect it in Sentinel / QRadar / EDR / Network? |
| **Validation** | How do I know it works? |
| **Posture** | How good is my detection, and how good is my program? |

Sigma, SigmaForge and RSigma **are not the interface**: they are **internal engines** of the backend.
The platform is the home of the Detection Engineer.

---

## 1. Document index

| # | Document | Content |
|---|-----------|-----------|
| 00 | `00-README.md` | This document. Index, principles, frozen decisions. |
| 01 | `01-vision-scope-and-principles.md` | Problem, goals, non-goals, personas, use cases, CardinalOps comparison. |
| 02 | `02-data-model.md` | **Phase 1.** The 16 entities + 12 additional entities, attributes, relationships, ERD. |
| 03 | `03-architecture.md` | Logical and physical architecture, C4, components, deployment, security. |
| 04 | `04-canonical-yaml-schema.md` | Complete `detection.yml`, field by field, with validation rules. |
| 05 | `05-git-repository-structure.md` | Repo layout, conventions, branching, CI/CD, GitOps. |
| 06 | `06-validation-and-testing.md` | Validation Runs, test types, Findings, evidence, backtesting, RSigma. |
| 07 | `07-posture-and-scoring.md` | Exact formulas for Coverage/Quality/Health/Effectiveness/Governance, SOC KPIs. |
| 08 | `08-lifecycle-and-workflows.md` | State machines, operational flows, drift, DEV→PROD promotion. |
| 09 | `09-implementations-sigma-and-translation.md` | Generated / Generated+Customized / Native, SigmaForge, translation drift. |
| 10 | `10-connectors-and-integrations.md` | Sentinel, QRadar, EDR, Network, Data Collector, Posture Engine. |
| 11 | `11-api-and-contracts.md` | REST/GraphQL API, endpoints, models, events, webhooks. |
| 12 | `12-ui-ux-and-screens.md` | Navigation map, wireframes of all screens. |
| 13 | `13-roadmap-and-mvp.md` | v0.1 / v0.2 / v0.3 / v1.0, exit criteria, migration plan for the existing catalog. |
| 14 | `14-risks-decisions-and-glossary.md` | ADRs, risks, assumptions, open questions, glossary. |
| - | `../backend/dep/dep/schemas/detection.schema.json` | JSON Schema for `detection.yml` (canonical contract, used by the CLI). |
| - | `reference/schema.sql` | PostgreSQL DDL for the platform database (reserved for the future database layer). |

---

## 2. Already frozen decisions (do not revisit without an ADR)

These decisions come from previous conversations and are considered **closed**.
Any change requires a new ADR in `14-risks-decisions-and-glossary.md`.

| ID | Decision | Rationale |
|----|----------|---------------|
| **D-01** | The root entity is **Detection**, not "rule". | A detection is a behavior; a rule is a technical artifact. |
| **D-02** | `Detection` (what) and `Implementation` (how) are **separate** entities. | QRadar's AQL and Sentinel's KQL are *two implementations of the same detection*, not two rules. |
| **D-03** | There are **four layers**: Intent / Implementation / Validation / Posture. | It is what sets DEP apart from "one giant Sigma". |
| **D-04** | **Git is the source of truth**. The database is a derived index. | Audit, review, history, PRs, rollback. |
| **D-05** | **A single GUI.** SigmaForge, Sigma and RSigma are backend components. | The engineer never "opens another tool". |
| **D-06** | `detection.yml` **is not** a Sigma YAML. Sigma is *one* of the possible logic formats. | Do not lose `binary_and()`, `_GetWatchlist()`, `summarize`, `make_set()`. |
| **D-07** | There are **three implementation types**: `generated`, `generated_customized`, `native`. | Not every detection should go through automatic translation. |
| **D-08** | Validation is a **first-class entity** (`ValidationRun`), not a `last_tested` field. | We must store what was tested, with what data, and what happened. |
| **D-09** | **Findings** are their own persistent entity. | A test produces findings that outlive the test. |
| **D-10** | **Detection metrics** and **program metrics** are distinguished. They are never mixed. | Different audiences: engineer vs SOC Manager. |
| **D-11** | Documentation lives in **Markdown next to the code**, not in external notes. | Almost direct migration, no loss. |
| **D-12** | The MVP is built against **10 representative detections**, not against the full catalog. | If the model represents those 10, it represents the full catalog. |
| **D-13** | ~~Environment is a dimension of `Implementation`.~~ **Superseded by ADR-013:** the environment is determined by the **branch** (`.dep/environments.yml`), not by the detection content. | Promotion is a `develop → main` merge and DEV<->PROD drift is a `git diff`. |
| **D-14** | The real state of the SIEMs is **discovered** via Connectors, not declared by hand. | Prevents the inventory from lying. |

---

## 3. Design principles

1. **Behavior outranks syntax.** Everything hangs off the Intent.
2. **Nothing is lost in migration.** The real KQL/AQL is always preserved verbatim.
3. **Everything is auditable.** Who, when, with what evidence, on which version.
4. **The platform does not lie.** If it has not been validated, it is shown as not validated.
5. **Open source and extensible.** Connectors and validators as plugins.
6. **Graceful degradation.** A detection without Sigma, without an owner or without tests still exists in the catalog - it just scores worse.
7. **Git-first, UI-second.** Everything the UI does can be done with a commit.

---

## 4. Project naming

`DEP` is used as the working acronym. Alternative names proposed for deciding later
(does not block development): `Bastion`, `Watchtower`, `Forge Control`, `DetectOps`, `Cardinal-OSS`.

Identifier prefixes:

| Prefix | Entity | Example |
|---------|---------|---------|
| `DET-` | Detection | `DET-0003` |
| `IMP-` | Implementation | `IMP-0003-SENTINEL` |
| `VAL-` | Validation Run | `VAL-2026-0842` |
| `FND-` | Finding | `FND-0001` |
| `EVD-` | Evidence | `EVD-2026-1187` |
| `DEP-` | Deployment | `DEP-2026-0311` |
| `TST-` | Test (definition) | `TST-KRB-BF-001` |
| `ADR-` | Architecture decision | `ADR-004` |

---

## 5. How to read this documentation

- If you are going to **design the database or the YAML** → documents 02, 04, 05.
- If you are going to **build the backend** → 03, 09, 10, 11.
- If you are going to **build the UI** → 12, 07, 08.
- If you are going to **migrate the existing catalog** → 13, 04, 05.
- If you are the **SOC Manager** → 01, 07, 13.
