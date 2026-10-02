# Auditeur — Architecture

Status: MVP skeleton (v0.1.0). This document is the canonical design record.

## 1. The central principle

> **Deterministic evidence first. Local AI second.**

Auditeur is not a wrapper around a language model. It is a deterministic audit
engine with an optional interpretation layer. The layering is one-directional
and enforced by types:

```
Facts        directly observed from the filesystem, Git, manifests, tools
   |
Evidence     an addressable reference to a fact (file:line range, command output,
   |         Git commit, dependency, configuration value, AST observation)
Findings     conclusions derived from one or more pieces of evidence
   |
AI reasoning interpretation of evidence, always subordinate to it
```

Rules that follow from the principle:

1. Every finding carries evidence. A finding with no evidence is a defect in the audit definition, not a finding.
2. AI output is a *draft*. It becomes a finding only after every evidence reference it cites has been re-verified against the repository model.
3. An AI claim whose evidence cannot be verified is retained but marked `unverified`; it is never silently promoted to fact and never deleted (deletion would hide model failure).
4. The model cannot change audit scope, severity rules or instruction hierarchy. Audit instructions are compiled-in constants; repository content is labelled data.
5. No aggregate "quality score" is produced. Status, severity and confidence are three orthogonal axes reported separately.

## 2. Read-only boundary

The audited repository is untrusted input and strictly read-only.

Permitted: read files, traverse directories, inspect Git metadata, run
allowlisted read-only analysis commands, capture stdout/stderr, parse manifests.

Forbidden, structurally: writing any file inside the audited tree, deleting,
renaming, formatting, applying automatic fixes, installing dependencies,
creating commits, altering Git state, inheriting a hostile environment into a
child process.

Enforcement is architectural rather than advisory:

- `auditeur-repository` is the only crate that touches the audited filesystem or spawns processes, and it exposes no write API.
- `PathGuard` canonicalises every candidate path and rejects anything that escapes the repository root (symlink and `..` traversal protection).
- `CommandRunner` executes an argv allowlist with `std::process::Command` (no shell), a scrubbed environment, a working directory pinned to the repository root, and a hard timeout.
- `ReadOnlyGuard` fingerprints the repository (relative path, size, mtime, content digest for text files) before and after an audit; integration tests fail if the fingerprint changes.

## 3. Workspace layout

Ten crates, acyclic, each with a single reason to exist. Boundaries are chosen
so that the core can be embedded in other front-ends (CLI today, Tauri later)
without dragging in terminal code.

```
crates/
  auditeur-model        domain types, zero I/O
  auditeur-config       strongly typed TOML configuration + AuditeurHome layout
  auditeur-repository   the read-only boundary: discovery, classification, Git, exec
  auditeur-languages    LanguageAnalyzer trait + per-language adapters
  auditeur-inference    InferenceBackend trait, backends, hardware detection, prompt fencing
  auditeur-audit        audit definitions, planner, deterministic checks, engine
  auditeur-report       run artifacts (manifest/findings/evidence) + report rendering
  auditeur-logging      one logging entry point: rolling file, redacted, level policy
  auditeur-tui          ratatui setup wizard and progress; state separate from terminal
  auditeur-cli          clap front-end, binary `auditeur`
```

Dependency direction:

```
model  <-  config
       <-  repository      <-  languages
       <-  inference
       <-  report
                             audit  <-  {model, config, repository, languages, inference}
                             tui    <-  {model, config, inference}
                             cli    <-  everything
```

There is no cycle and no back-edge into a lower layer. `auditeur-audit` does not
know about terminals; `auditeur-tui` does not know about the audit engine;
`auditeur-logging` knows the configuration and the redactor, and nothing else
knows about `auditeur-logging` — the engine emits `tracing` records and stays
unaware of where they end up.

## 3.1 The state home

One directory holds everything Auditeur owns. `AuditeurHome` in
`auditeur-config` is the only place that decides where, and it is resolved by a
*pure function* of the environment mapping and the home directory
(`AuditeurHome::discover_with`), so the rule is testable without touching the
process environment:

```text
--home DIR  →  .auditeur-project in the repository  →  AUDITEUR_HOME  →  $HOME/auditeur
```

A relative root is refused: a run whose state location depends on the working
directory is a bug waiting for a different shell. The layout beneath the root is
configurable, but only with **relative** sub-paths, which keeps the state
directory movable and restorable from a backup.

Creation is lazy. `setup` writes the documented tree, the logger creates its own
directory, and a directory appears when something first needs it — `doctor`
describes the layout and creates nothing. `AuditeurHome::ensure` is the one
function that creates the top-level tree, and it never creates anything below
`cache/`.

### Logs are not evidence

```text
runs/<run-id>/   reproducible audit artefacts — the evidence
logs/            operational and debugging output — not evidence
```

Nothing in the audit model reads a log file, and no finding may be derived from
one. This is a deliberate separation of two things that are routinely conflated:
an artefact that must be reproducible and citable, and a stream that is
best-effort, rotated and deleted.

## 4. Core traits

```rust
// auditeur-languages
pub trait LanguageAnalyzer: Send + Sync {
    fn id(&self) -> Language;
    fn detect(&self, model: &RepositoryModel) -> DetectionResult;
    fn files(&self, model: &RepositoryModel) -> Vec<SourceFileRef>;
    fn dependencies(&self, ctx: &LanguageContext) -> DependencyGraph;
    fn tests(&self, ctx: &LanguageContext) -> TestInventory;
    fn analyze(&self, ctx: &LanguageContext) -> LanguageAnalysis;
}

// auditeur-audit
pub trait Check: Send + Sync {
    fn id(&self) -> &'static str;
    fn definition_id(&self) -> &'static str;
    fn category(&self) -> AuditCategory;
    fn severity(&self) -> Severity;
    fn kind(&self) -> CheckKind;               // Deterministic | AiAssisted | Hybrid
    fn run(&self, ctx: &AuditContext<'_>) -> Result<Vec<Finding>, AuditError>;
}

// auditeur-inference
pub trait InferenceBackend: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> BackendCapabilities;
    fn health(&self) -> HealthReport;
    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, InferenceError>;
}

// auditeur-report
pub trait ReportRenderer {
    fn format(&self) -> OutputFormat;           // Markdown | Json | Sarif
    fn render(&self, report: &AuditReport) -> Result<String, ReportError>;
}

// auditeur-audit (progress is a sink, not a dependency)
pub trait ProgressSink: Send + Sync {
    fn stage(&self, stage: AuditStage, detail: &str);
}
```

The traits are deliberately small. Anything that can be a pure function is a
pure function; anything that needs the outside world is behind one of these.

## 5. Data models

All types live in `auditeur-model` and are `serde`-serialisable, so the run
artifacts are the same structures the report renderer consumes. No parallel
"report DTO" layer exists.

```
Evidence
  id            stable, content-derived (sha256 over kind+target+detail)
  kind          FileRange | CommandOutput | GitRef | Dependency | ConfigValue
                | AstObservation | ToolResult | FileContent
  location      structured; e.g. FileRange { path, start_line, end_line }
  summary       human-readable, one line
  excerpt       bounded, secret-redacted, never the whole file
  digest        sha256 of the exact bytes the observation came from

Finding
  id            deterministic: <definition>/<check>/<discriminator>
  status        Pass | Info | Warn | Fail
  severity      Info | Low | Medium | High | Critical
  confidence    Low | Medium | High
  category      one of the 15 audit categories
  title / description / recommendation
  evidence      Vec<EvidenceRef> (references into the run evidence store)
  source        Deterministic | AiAssisted { backend, model, run_id, verified }
  language      Option<Language>

RunManifest
  auditeur_version, audit_schema_version, audit_definition_versions
  model { name, version, checksum, backend }
  repository { path, git: Option<GitState>, fingerprint }
  started_at, finished_at, unix_timestamp
  detected_languages, enabled_categories, skip_reasons
  files_inspected, bytes_inspected, tools_executed
  counts { pass, info, warn, fail }
  limitations  (explicit list of what this run could not do)
```

### Status, severity and confidence

These three are orthogonal and must not be collapsed:

| Axis | Values | Meaning |
| --- | --- | --- |
| `status` | `PASS`, `INFO`, `WARN`, `FAIL` | Outcome of the check: satisfied, neutral observation, violation that warrants attention, violation of a hard requirement. |
| `severity` | `Info`, `Low`, `Medium`, `High`, `Critical` | Impact **if** the issue is real. Declared by the audit definition, not chosen by the model. |
| `confidence` | `Low`, `Medium`, `High` | Certainty of the claim. Deterministic checks are `High` by construction; AI-assisted findings carry the verifier's assessment. |

A `WARN` with `Critical` severity and `Low` confidence is a meaningful,
reportable state — it means "if true, this is serious; we could not confirm it".
Collapsing these into one number would destroy exactly the information an
auditor needs.

## 6. Pipeline

```
Repository Discovery      bounded walk, classification, Git probe, fingerprint
        |
Repository Model          typed inventory: files, languages, manifests, stats
        |
Deterministic Analysis    language adapters: dependencies, tests, project metadata
        |
Audit Planning            resolve definitions -> checks -> tasks; record scope
        |
Targeted AI Analysis      structured tasks over selected evidence (skippable)
        |
Evidence Verification     every AI citation re-resolved against the repository
        |
Finding Validation        severity/category/schema checks, dedup, redaction
        |
Structured Findings       serialisable, evidence-linked
        |
Report Generation         Markdown report + run artifacts (manifest/findings/evidence)
```

Each stage is a separately testable unit. `AuditEngine::run` accepts
`AuditOptions` (root path, config, backend, `enable_ai`, limits) and returns an
`AuditReport`; the CLI and the TUI are both thin clients of that call.

Failure policy: a missing toolchain, an unreachable backend or an unreadable file
never aborts the audit silently. The stage records a *limitation*, the audit
continues with the evidence it has, and the limitation is printed in the report.
The only hard failures are `2`-class errors: bad configuration, unreadable
repository root, unwritable output directory.

## 7. AI integration and prompt-injection defence

The AI has no privileges. It receives:

```
[system]     compiled-in instruction block: role, output schema, rules
[user]       audit task: id, objective, allowed evidence references,
             and the evidence payload inside an explicit untrusted-data fence
```

Defences, all of them structural rather than prompt-based:

- The instruction/schema block is a Rust constant. Repository content cannot reach it.
- Repository content is inserted only inside `<<<UNTRUSTED-REPOSITORY-DATA>>>` fences, with the fence token stripped from the payload so it cannot be forged.
- The system block states explicitly that fenced content is data and that any instruction inside it must be reported, not obeyed.
- Output must be schema-valid JSON; anything else is a parse failure recorded as a limitation.
- Every evidence reference the model emits is re-resolved against the repository model. Unresolvable references downgrade the finding to `unverified`.
- Severity comes from the audit definition, not from the model's prose.
- The model never sees secrets: excerpts are redacted before they leave the process.

## 8. Inference design

`InferenceBackend` is provider-agnostic. The MVP ships:

- `OpenAiCompatBackend` — HTTP client for any OpenAI-compatible `/v1/chat/completions` endpoint (LM Studio, Ollama, `llama.cpp --server`, vLLM). Configured by `model.toml`.
- `MockBackend` — an explicit test double, used by the deterministic tests and by `--no-ai` style runs. It is documented as a double, never as a capability.

Hardware acceleration is reported honestly. `hardware::detect()` probes the
real machine (Apple Silicon → Metal, `nvidia-smi` → CUDA with the reported
driver version, otherwise CPU) and `doctor` prints `-` for what is absent.
No backend claims a capability it does not have; in-process accelerated
inference (`llama.cpp` with `cpu`/`metal`/`cuda` Cargo features) is the next
iteration and will be feature-gated per backend, not simulated.

## 9. Configuration

TOML, strongly typed, one file per concern:

```
~/auditeur/config/auditeur.toml   project, report, paths, logging
~/auditeur/config/model.toml      backend, endpoint, model, sampling, timeouts
~/auditeur/config/audit.toml      enabled categories, severities, thresholds, definitions
```

Precedence: compiled defaults → files → `AUDITEUR_*` environment variables →
CLI flags. Unknown keys are tolerated (forward compatibility) and reported by
`doctor`; invalid values are hard errors with a file/line-qualified message.
Absence of configuration is not fatal: `auditeur <path>` applies defaults and
tells the user to run `setup`.

`[paths]` and `[logging].file` name **relative** sub-paths of the home. The
resolved state root is never written to a file: a configuration that carried an
absolute path would stop being portable, and restoring it on another machine
would point at a directory that does not exist. Validation refuses an absolute
path, a `..` that escapes the home, and a blank value, naming the key.

### 9.1 Logging

One entry point (`auditeur-logging::init`), called once from the binary, and one
file:

```text
auditeur.log      active
auditeur.log.1    previous, … up to max_files
```

* **Size-based rotation.** `max_size_mb` and `max_files` are passed to
  `file-rotate` as a byte count and a file count. `max_files` counts *rotated*
  files, so `5` means six files on disk.
* **Level policy.** `--log-level` (CLI) overrides `[logging].level`, which
  overrides the default `info`. The flag is per-process and never writes to the
  configuration.
* **Third-party pinning.** A curated list of targets (`ureq`, `rustls`, `hyper`,
  `h2`, `mio`, `want`) is pinned at `warn`, so running Auditeur at `debug` does
  not pour a transport library's payloads into the log. A crate that is not on
  the list is not pinned, which is why the list is short and explicit.
* **Redaction before the file handle.** The redacting writer sits *inside* the
  non-blocking appender: bytes are redacted on the way in, never written and then
  scrubbed. It re-assembles lines before redacting — a formatting layer may hand
  over one line in several calls, and a credential straddling two of them would
  survive a per-call pass — and it holds back an open private-key block until the
  footer arrives, because that block is the one credential shape that spans
  lines.
* **Best effort.** A log that cannot be written is reported on standard error and
  the command continues: the audit is the deliverable and the log is not.

## 10. Audit definitions

Audit knowledge is declarative and versioned, not compiled in:

```toml
[audit]
id = "security"
version = "1.0.0"
title = "Security"

[[checks]]
id = "committed-secrets"
title = "Credentials committed to the repository"
kind = "deterministic"        # deterministic | ai_assisted | hybrid
category = "security"
severity = "high"

[[checks]]
id = "unsafe-process-execution"
title = "Dangerous process execution patterns"
kind = "hybrid"
category = "security"
severity = "medium"
```

Definitions ship embedded in the binary (so the MVP works offline), can be
overridden from `~/auditeur/config/definitions/`, and their ids and versions
are recorded in every run manifest. A future release adds a richer condition
language; the loader is versioned from day one so that change is not a breaking
one.

## 11. Reporting

Primary human-readable output: Markdown, written to
`~/auditeur/<source-folder>/audit_<unix_timestamp>.md`, containing
executive summary, repository information, environment, detected languages,
audit scope, methodology, findings, evidence, recommendations, tool/test
results, limitations and reproducibility information.

Machine-readable output: `runs/<timestamp>/manifest.json`, `findings.json`,
`evidence.json` — written unconditionally, on every run (Markdown is a view, not
the record).

`ReportRenderer` is a trait with `OutputFormat::{Markdown, Json, Sarif}`. JSON
is implemented; SARIF is declared and returns an explicit "not implemented"
error rather than a stub file — a roadmap target, not fake support.

## 12. Front-ends

`auditeur-cli` (clap) provides `auditeur [path]`, `audit`, `setup`, `doctor`,
`update`, with the default command auditing the current directory.

`auditeur-tui` (ratatui) owns the setup wizard and long-running progress. Its
state machine is a plain Rust struct driven by `KeyEvent` values, so wizard
transitions are unit-testable without a terminal; only the rendering and event
loop touch crossterm. Nothing in the engine depends on either front-end.

## 13. MVP boundary

Implemented now: workspace, CLI, setup wizard, audit, doctor, TOML config,
repository discovery, Git metadata, language detection for all eleven targets,
deep analysis for Rust/Go/Python/Node, evidence model, finding model,
deterministic checks across several categories, model abstraction with one real
backend, Markdown reporting, run manifest, read-only guarantees, tests.

Deliberately not implemented now: in-process accelerated inference, model
download/management, the audit-definition condition language, SARIF output,
Tauri, incremental audits, audit comparison, network-fetching package metadata.
Each is listed with its intended design in DEVELOPMENT.md.
