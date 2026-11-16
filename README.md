# DEP - Detection Engineering Platform

**DEP helps a security team write, document, version and publish its detection rules in an orderly way, in one place, with automatic quality checks.**

> **Project status:** early version (`0.1.0`). Today DEP covers *documenting, validating and versioning* detections. *Automatically deploying them to Microsoft Sentinel* is designed but not built yet (see [Where it can grow](#9-where-it-can-grow)).

---

## Table of contents

1. [What is DEP and what is it for?](#1-what-is-dep-and-what-is-it-for)
2. [The problem it solves](#2-the-problem-it-solves)
3. [How it works at a glance](#3-how-it-works-at-a-glance)
4. [Key concepts (simple glossary)](#4-key-concepts-simple-glossary)
5. [What is covered today and what is not](#5-what-is-covered-today-and-what-is-not)
6. [The detections repository, folder by folder](#6-the-detections-repository-folder-by-folder)
7. [Environments and branches: how to go from DEV to PROD](#7-environments-and-branches-how-to-go-from-dev-to-prod)
8. [Manual usage examples, step by step](#8-manual-usage-examples-step-by-step)
9. [Where it can grow](#9-where-it-can-grow)
10. [Structure of this repository](#10-structure-of-this-repository)
11. [More documentation](#11-more-documentation)

---

## 1. What is DEP and what is it for?

A **detection** is a rule that tells a security system (for example Microsoft Sentinel) *"alert me when you see this suspicious behavior"*. For example: *"alert me if someone fails to sign in 10 times in a row"*.

A security team can end up with dozens or hundreds of these rules. Over time it is easy to lose control: who wrote it? What exactly does it do? Did we test it? Which version is in production?

**DEP is the "organized archive with a security guard" for those rules.** With DEP, a person can:

| Can... | How |
|---|---|
| **Document** each rule | One file per detection with its goal, severity, MITRE ATT&CK technique, owner, etc. |
| **Keep the real rule** next to its description | The query (KQL for Sentinel, AQL for QRadar) lives right beside the description |
| **Separate by environment** | DEV (testing) and PROD (production) are handled with Git branches |
| **Keep things tidy** | A validator checks that the description is complete and uses only allowed values |
| **Keep version control** | Every change is recorded: who, when and why |
| **Make correct commits** | One command validates everything and enforces a standard commit message format |

**The end goal:** the team works in a Git repository, and an automation (GitHub Actions) publishes the rules to Sentinel. DEP prepares and protects that chain. Its inspiration is a commercial product; the goal is to offer an open, extensible alternative with more capabilities.

---

## 2. The problem it solves

**Before**, knowledge was spread across three places that did not talk to each other:

```
   Notes                    Sentinel                   QRadar
 (documentation)         (live KQL rules)          (old AQL rules)
        │                       │                        │
        └──────── nobody knows how they relate ──────────┘
```

Real consequences: the same detection appeared as two different rules (one in each system), there was no way to know what was tested or when, and the DEV version could differ from PROD without anyone noticing.

**With DEP**, everything lives together, in a single place, with history:

```
                  ┌────────────────────────────────┐
                  │     Detections repository      │
                  │  (Git: the single real source) │
                  │                                │
                  │  description + query + docs    │
                  └────────────────────────────────┘
```

> **Golden rule of the project:** Git is the *source of truth*. What is in Git is what exists. Anything else (databases, screens, reports) is a derived view.

---

## 3. How it works at a glance

There are **two separate things**. It is worth not mixing them up:

| What | What it is | Analogy |
|---|---|---|
| **`dep-platform`** (this project) | The **tool**: the `dep` program, its validation rules and its documentation. It is public and **contains no detections** | The *word processor* |
| **Your detections repository** | The **content**: your team's detections. It is **yours, private and independent** of this project | The *documents* you write with it |

DEP **does not include or need any real detection**. Each person or team creates their own detections repository with `dep init-repo` (see [section 8](#8-manual-usage-examples-step-by-step)) and keeps it wherever they want: on their GitHub, on their server, in private. DEP never sends that content anywhere.

A person's workflow is:

```
  1. Create or edit        2. Validate             3. Save (commit)         4. (Future) Publish
  a detection       ───►   with `dep`        ───►  with `dep commit`  ───►  to Sentinel
  `dep new-detection`      "is it correct?"        on a Git branch          with GitHub Actions
```

The `dep` program acts as an **automatic reviewer**: if something is wrong, it reports a clear error code **before** anything is saved.

---

## 4. Key concepts (simple glossary)

| Term | What it means, in simple words |
|---|---|
| **Detection** | A *behavior* we want to detect. It is the idea ("Kerberos brute force"), not the technical query. Identified as `DET-0001`. |
| **Implementation** | *How* that idea is detected in a specific system. One detection can have an implementation in Sentinel (KQL) and another in QRadar (AQL). Identified as `IMP-0001-SENTINEL`. |
| **`detection.yml`** | The **description file** of a detection. A text file with fields (name, severity, owner...). |
| **KQL / AQL** | The query languages of Sentinel and QRadar. This is the "real" rule. |
| **Taxonomy** | The **lists of allowed values**, like a drop-down menu. For example, severity can only be `info`, `low`, `medium`, `high` or `critical`. It prevents one person writing "urgent" and another "High". |
| **Policy** | The **rules of the detection program**: for example, which tests are required before moving something to production. |
| **Validate** | Ask `dep` to check that everything is complete and correct. |
| **Git** | The system that keeps the **full history** of changes of the repository. |
| **Commit** | A "saved snapshot" of the changes, with a message explaining what was done. |
| **Branch** | A parallel line of work. It lets you work without affecting what is already approved. |
| **Environment** | The "place" where a rule lives: `dev` (testing) or `prod` (production). In DEP **the branch determines it** (see section 7). |
| **Version** | The number that goes up when a rule changes (`1.0.0` to `1.1.0`). |
| **MITRE ATT&CK** | A public catalog of attack techniques. Each detection states which technique it covers. |

---

## 5. What is covered today and what is not

DEP organizes the work into **four layers**. This table is honest about the current state:

| Layer | Question it answers | Status today |
|---|---|---|
| **1. Intent** | What behavior do I want to detect? | **Covered.** Complete description, with MITRE, severity, owner and documentation, validated against the allowed lists. |
| **2. Implementation** | How do I detect it in Sentinel or QRadar? | **Partial.** The query is stored and checked for existence, but DEP does not yet generate it or publish it to Sentinel. |
| **3. Validation** | How do I know it works? | **Declared only.** The description can state tests and test data, but DEP does not run them yet. |
| **4. Posture** | How good is my detection and my program? | **Not built yet.** MITRE coverage, scores and reports are designed, not built. |

### What the `dep` program does today

| Command | What it is for |
|---|---|
| `dep init-repo` | Creates a new detections repository, with all the folders and basic lists |
| `dep new-detection` | Creates a new detection: assigns the next `DET-NNNN` id, creates the folders and fills `detection.yml` from the standard template |
| `dep validate` | Checks a `detection.yml` file (its structure only) |
| `dep validate-repo` | Checks the **whole repository**: descriptions, allowed lists, referenced files, duplicate IDs and the environments configuration |
| `dep commit` | Validates, warns if you forgot to bump the version, enforces a standard message format and saves the commit. It refuses to commit directly on the production branch |

### What it does **not** do yet

- It does not publish rules to SIEM (Sentinel, QRadar, etc).
- It does not run detection tests.
- It does not compute MITRE coverage or scores.
- It has no graphical interface or database (designed in `docs/`, not built yet).

---

## 6. The detections repository, folder by folder

This is the repository where **your** team's rules live. You create it with `dep init-repo` and can name it whatever you want. This is what it looks like inside and **what each part is for**:

```
my-detections-repo/
├── .dep/                  <- DEP configuration for this repository
├── taxonomy/              <- The lists of allowed values
├── detections/            <- The detections (this is where you work 95% of the time)
├── shared/                <- Pieces reusable across detections
├── docs/                  <- Documentation of the detection program (not of rules)
├── coverage/              <- Coverage reports (generated automatically)
├── reports/               <- Exported reports
├── tools/                 <- Helper scripts for the repository
├── README.md              <- Repository introduction
├── CONTRIBUTING.md        <- How to collaborate: workflow and team rules
├── CODEOWNERS             <- Who must approve changes
└── .gitignore             <- Files Git must ignore
```

### `.dep/` - the configuration

| File | What it is for |
|---|---|
| `environments.yml` | **Branch to environment map.** It says that the `develop` branch is DEV and `main` is PROD. Required. |
| `policies.yml` | The program's **policies**: which validations are required to move to production, how often to review a rule, quality thresholds. DEP requires it to exist; automatically enforcing these policies is future work. |
| `config.yml` | General data about the repository (name, format version). Almost empty today. |

### `taxonomy/` - the lists of allowed values

This is the "list of allowed options". If a description uses a value that is **not in the list**, `dep validate-repo` flags it as an error. That way the whole team speaks the same language.

| File | What it defines | Validated today? |
|---|---|---|
| `severity.yml` | Severity levels and their response time (`high` = 60 min) | Yes |
| `layers.yml` | Detection areas: identity, endpoint, network, cloud... | Yes |
| `data-sources.yml` | Logical data sources (for example Windows security events) | Yes |
| `platforms.yml` | Systems where rules live (Sentinel, QRadar...) and their language | Yes |
| `behaviors.yml` | Vocabulary of attacker behaviors (`brute-force`...) | Yes |
| `owners.yml` | Responsible teams and their contact | Yes |
| `environments.yml` | Environments (`dev`, `staging`, `prod`) and whether they require approval | Yes |
| `log-sources.yml` | How each source materializes in each platform (tables, events) | Must only exist |
| `scoring.yml` | Weights for future quality scores | Must only exist |
| `attack/` | Copy of the MITRE ATT&CK catalog in use | Reserved |

### `detections/` - the catalog

Each detection has **its own folder**, named `DET-NNNN-short-name`:

```
detections/DET-0001-example/
├── detection.yml                  <- The description: what it is, severity, MITRE, owner...
├── implementations/
│   └── sentinel/
│       └── rule.kql               <- The real query for Sentinel
└── documentation/
    └── overview.md                <- Plain-text explanation: why it exists, how to investigate
```

| Part | What it contains |
|---|---|
| `detection.yml` | The **metadata**: name, version, status, severity, goal, MITRE technique, data sources, owner. It says where the other files are. |
| `implementations/<platform>/` | The **real query**. There is one folder per platform (`sentinel`, `qradar`). **There are no `dev`/`prod` folders**: the branch gives the environment. |
| `documentation/` | Markdown documents (simple text): overview, how to investigate an alert, known false positives, tuning history. |
| `tests/` *(optional)* | Test data that shows the rule fires. |

> **Important rule:** `detection.yml` **never contains the query pasted inside**. It only points to the file (`implementations/sentinel/rule.kql`). That way the query can be read, compared and reviewed like normal code.
>
> **The ID is forever.** `DET-0001` identifies that detection even if it is retired. It is never reused.

### `shared/` - reusable pieces

Things several detections can share, so you do not copy and paste:

- `functions/` - reusable query functions (for example, to normalize account names).
- `exclusions/` - global exclusions (for example, the list of authorized scanners).
- `enrichment/` - inventory of external lists used by the rules (watchlists).
- `snippets/` - frequently used query fragments.

### The other folders

| Folder / file | What it is for |
|---|---|
| `docs/` | Documentation **of the program** (detection policy, severity guide, conventions, response playbooks in `runbooks/`). Not per-rule documentation: that goes with each detection. |
| `coverage/` | **Generated** output, not edited by hand (MITRE coverage maps, accepted gaps). |
| `reports/` | Reports exported per period (for example, a quarterly report). |
| `tools/` | The repository's own scripts (importers, helpers). |
| `CODEOWNERS` | GitHub file that defines **who must approve** changes to each part. |
| `CONTRIBUTING.md` | Team collaboration guide. |

> When you create a new repository with `dep init-repo`, `shared/`, `coverage/`, `reports/`, `tools/` and `docs/runbooks/` start **empty** (with a `.gitkeep` file that only reserves the place). They fill up as your detection program grows.

### An example description file, explained

This is a minimal description file. The `#` comments explain each part:

```yaml
schema_version: "1.0.0"            # version of the file format
id: DET-0001                        # unique, permanent identifier
name: Brute force example           # readable name
version: "1.0.0"                    # version of THIS detection; goes up when it changes
status: draft                       # stage: draft, testing, tuning, active, deprecated...
description: Detects many failed sign-in attempts from the same IP address.
severity: medium                    # must exist in taxonomy/severity.yml
detection_type: signature

intent:                             # the INTENT: what we want to detect and why
  summary: Identify brute force attacks against user accounts.
  adversary_behavior:
    - brute-force                   # must exist in taxonomy/behaviors.yml

implementations:                    # the HOW: the query on each platform
  - id: IMP-0001-SENTINEL
    platform: sentinel              # must exist in taxonomy/platforms.yml
    type: native
    status: draft
    enabled: false                  # not published yet
    version: "1.0.0"
    logic:
      language: kql
      file: implementations/sentinel/rule.kql   # the file with the query
    schedule:
      frequency: PT5M               # runs every 5 minutes
      lookback: PT1H                # looks at the last hour

documentation:
  overview: documentation/overview.md           # the file must exist

governance:
  owner:
    team: detection-engineering     # must exist in taxonomy/owners.yml
```

---

## 7. Environments and branches: how to go from DEV to PROD

In DEP **the Git branch you are on decides the environment**, not a field inside the description file. The reason: this way a rule is *promoted* from DEV to PROD simply by **merging** one branch into another, without editing anything.

A **branch** is a parallel line of work. Think of it as a separate draft of the official document.

```
  feature/DET-0058-new-rule         <- you work here (personal draft)
              │
              │  Pull Request + review
              ▼
          develop                   <- DEV: what is tested / deployed to DEV
              │
              │  Pull Request + approval (someone other than the author)
              ▼
            main                    <- PROD: what is approved and deployed to production
```

| Branch | Environment | Can I save directly here with `dep commit`? |
|---|---|---|
| `feature/...`, `tune/...` | None (work in progress) | Yes |
| `develop` | `dev` | Yes |
| `main` | `prod` | **No.** It requires review: you get there through a Pull Request |

This protection comes from `taxonomy/environments.yml`: the `prod` environment has `requires_approval: true`, so its branch is protected. (This is a local aid; the real protection must also be enabled on GitHub.)

**Extra benefit:** knowing what differs between DEV and PROD is simply comparing two branches with Git.

---

## 8. Manual usage examples, step by step

These examples use **test data**; they are for practicing without risk.

### 8.0 Setup (one time only)

You need **Git** and **Python 3.10 or higher**. Check your version:

```bash
python3 --version
```

> **Careful on Mac:** the Python that ships with the system is often 3.9, which **does not work**. If you see `3.9.x`, install a newer one (for example `brew install python@3.12`) and use `python3.12` instead of `python3` in the commands below.

From the `dep-platform` folder:

```bash
python3 -m venv .venv                 # creates an isolated environment
source .venv/bin/activate             # activates it (on Windows: .venv\Scripts\activate)
python -m pip install --upgrade pip   # avoids errors with old pip versions
pip install -e backend/dep            # installs the `dep` program
dep --help                            # checks that it works
```

> Every time you open a new terminal, run `source .venv/bin/activate` again to be able to use `dep`.
>
> Technical details of each command are in [`backend/dep/README.md`](backend/dep/README.md).

### 8.1 Create a new detections repository

```bash
dep init-repo my-repo                 # creates the structure and the basic lists
cd my-repo
git init -b develop                   # starts the history on the DEV branch
dep commit -m "chore: init repo"      # first commit (allowed even on main)
```

### 8.2 Create your first detection

`dep` creates the folder, assigns the next free id and fills `detection.yml` from the standard template. From inside your detections repository:

```bash
dep new-detection "Kerberos Brute Force"
```

```
Created DET-0001: detections/DET-0001-kerberos-brute-force
Platforms: sentinel
```

The name is used as typed in `detection.yml`; the folder name is lowercase with spaces replaced by `-`. The next id is always the highest existing one plus one.

To choose the platform (it must exist in `taxonomy/platforms.yml`; the option can be repeated):

```bash
dep new-detection "Kerberos Brute Force" --platform qradar
dep new-detection "Kerberos Brute Force" --platform sentinel --platform qradar
```

The result:

```
detections/DET-0001-kerberos-brute-force/
├── detection.yml                       <- standard template, ready to fill in (TODO markers)
├── implementations/sentinel/rule.kql   <- placeholder, write the query here
└── documentation/overview.md           <- placeholder
```

Then complete the TODO fields (description, MITRE ids, data source table, owner...), write the query and continue with validation (8.3).

### 8.3 Validate (the most important step)

```bash
dep validate-repo .
```

If everything is fine, the last line of the output reports zero errors:

```
1 detection(s), 0 error(s)
```

**If you forgot to create the `overview.md` file**, `dep` tells you:

```
detections/DET-0001-example/detection.yml
  DEP-FIL-004  DET-0001  documentation/overview  documentation/overview.md

1 detection(s), 1 error(s)
```

**If you write a severity that is not in the list** (`severity: urgent`):

```
  DEP-TAX-013  DET-0001  severity  'urgent' not found in taxonomy/severity.yml
```

Each error shows: **the code**, **the detection**, **where it is** and **what is wrong**.

| Code | Meaning |
|---|---|
| `DEP-SCH-001` | The description has a misspelled, missing or wrongly typed field |
| `DEP-FIL-004` | The description points to a file that does not exist |
| `DEP-DUP-012` | Two detections have the same ID |
| `DEP-TAX-013` to `019` | A value is not in its allowed list (severity, area, data source, platform, behavior, team) |
| `DEP-ENV-002` | The environments configuration uses an environment that does not exist |
| `DEP-ENV-003` | Two branches point to the same environment |
| `DEP-ENV-004` | An implementation still carries the `environment` field (no longer used; delete it) |
| `DEP-CFG-020` | A required configuration file is missing or malformed |

### 8.4 Save the change (commit)

First, **see what it would do** without saving anything:

```bash
dep commit --dry-run -m "feat(DET-0001): add example brute force detection"
```

If it all looks good, save it for real (if you omit `-m`, `dep` asks you for the message):

```bash
dep commit -m "feat(DET-0001): add example brute force detection"
```

Real output:

```
Branch: develop (environment: dev)
3 change(s): 2 material, 1 detection-support, 0 config, 0 other
Validation OK (1 detection(s)).
Committed db06dab: feat(DET-0001): add example brute force detection
```

`dep commit` does this for you: **checks** -> **validates** -> **stages** the changes -> **saves** the commit.

#### The message format

Messages must follow `type(scope): description`. The allowed types:

| Type | When to use it |
|---|---|
| `feat` | New detection or new implementation |
| `fix` | Fix a logic error |
| `tune` | Adjust or add an exclusion |
| `docs` | Documentation-only changes |
| `test` | Changes to tests |
| `valid` | Record of a validation |
| `find` | Open or close a finding |
| `deprecate` | Mark a rule as obsolete |
| `chore` | Maintenance (taxonomies, configuration) |
| `breaking` | Change that breaks compatibility |

If the message does not follow the format, `dep` rejects it and **saves nothing**:

```
Invalid commit message. Expected: type(scope): subject   (types: feat, fix, tune, ...)
```

### 8.5 Modify an existing detection (and bump the version)

When you change the query or the description, **bump the `version`** in `detection.yml` (for example from `1.0.0` to `1.1.0`).

If you forget, `dep` warns you and asks you to confirm:

```
WARNING: detections/DET-0001-example: version unchanged (1.0.0)
Commit anyway? [y/N]:
```

Answer `n`, bump the version and run `dep commit` again. With the version bumped, it asks nothing:

```
Branch: develop (environment: dev)
2 change(s): 2 material, 0 detection-support, 0 config, 0 other
Validation OK (1 detection(s)).
Committed 38fe1d7: tune(DET-0001): limit results
```

### 8.6 Work safely with branches

For a change you want reviewed before it reaches DEV:

```bash
git checkout -b feature/DET-0002-new-rule       # creates your work branch
# ...edit files...
dep validate-repo .
dep commit -m "feat(DET-0002): add new rule"
```

Then you open a **Pull Request** on GitHub into `develop`. Once approved and tested, another PR from `develop` into `main` promotes it to production.

If you try to save directly on `main`, `dep` stops you:

```
Branch 'main' is protected (environment 'prod' requires approval).
Commit on a work branch and open a pull request, or pass --allow-protected.
```

### 8.7 What happens when something fails

| Situation | What `dep` does |
|---|---|
| Validation fails | Shows the errors and **saves nothing** |
| You forgot to bump the version | Warns and asks for confirmation |
| The message does not have the right format | Rejects it and **saves nothing** |
| You are on a protected branch | Refuses to save |
| There is nothing to save | Says so and exits without error |

**`dep` never deletes or modifies your files.** It only reads, validates and saves the commit.

---

## 9. Where it can grow

> This is a **proposed roadmap**, not a promise. The order can change according to the team's priorities.

| Stage | What it would bring | What it is for |
|---|---|---|
| **Repository report** (`dep report`) | Summary of how many detections there are, by status and severity, MITRE coverage and which fields are missing | See at a glance what is left to complete. First step of the Posture layer |
| **Sentinel generator** (`dep build sentinel`) | Convert each detection into a file Sentinel understands (Bicep) | The step before publishing automatically |
| **Automatic publishing** | Connect the repository to GitHub and to *Microsoft Sentinel Repositories* (Microsoft's official CI/CD feature): when a change is approved, GitHub Actions deploys it | Go from "documenting" to "deploying" with no manual steps |
| **Branch and PR commands** (`dep branch`, `dep push`, `dep pr`) | Create branches and Pull Requests from the same program | Manage the whole cycle from one place |
| **Test execution** | Run each detection's test data and store the result | Validation layer: "how do I know it works?" |
| **Posture and scores** | MITRE coverage, quality and health of each rule, program indicators | Posture layer: measure how good the program is |
| **More platforms** | QRadar, EDR, network, etc. | One source of truth for every system |
| **Database, API and screens** | A queryable catalog with a graphical interface | See everything without touching files. Designed in `docs/`, not built yet |
| **Open source** | Publish the core (the `dep` program, the format and the validator) under an open license | Let other teams use it and contribute |

The full vision for each one is in the [`docs/`](docs/) folder.

### Known limits today

- Rules cannot be published automatically yet.
- To generate Sentinel rules, data that is optional in the description today will be needed, such as `schedule` (run frequency) or entity mapping. The future generator will warn when they are missing.
- The project license is still to be defined.
- The description file format (`detection.yml`) may change while the project is before version 1.0. The latest major change was removing the environment from the file (see `docs/14-risks-decisions-and-glossary.md`, ADR-013).

---

## 10. Structure of this repository

```
dep-platform/
├── backend/dep/        <- The `dep` program (Python code, tests and its technical README)
├── docs/               <- Design documentation: vision, data model, YAML schema, roadmap
├── frontend/           <- Reserved for the future graphical interface (empty for now)
└── README.md           <- This document
```

| Folder | Who it is for |
|---|---|
| `backend/dep/` | Anyone who wants to use `dep` in detail or modify the program |
| `docs/` | Anyone who wants to understand **why** it was designed this way |

**Scope of this repository:** it contains the current **core**: the `dep` program, the detection format and the validations. The database (PostgreSQL) and API layer, designed in `docs/`, is not part of this repository yet.

---

## 11. More documentation

| If you want to... | Read |
|---|---|
| Use the commands in technical detail | [`backend/dep/README.md`](backend/dep/README.md) |
| Understand the problem, the goals and who it serves | [`docs/01-vision-scope-and-principles.md`](docs/01-vision-scope-and-principles.md) |
| See all the fields of `detection.yml` | [`docs/04-canonical-yaml-schema.md`](docs/04-canonical-yaml-schema.md) |
| Understand the repository layout and the branch flow | [`docs/05-git-repository-structure.md`](docs/05-git-repository-structure.md) |
| Learn how quality will be measured (future) | [`docs/07-posture-and-scoring.md`](docs/07-posture-and-scoring.md) |
| See the plan by versions | [`docs/13-roadmap-and-mvp.md`](docs/13-roadmap-and-mvp.md) |
| Consult design decisions and the glossary | [`docs/14-risks-decisions-and-glossary.md`](docs/14-risks-decisions-and-glossary.md) |
| An index of everything | [`docs/00-README.md`](docs/00-README.md) |
