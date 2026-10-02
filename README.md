# Auditeur — Local Evidence-Driven Software Auditor

Auditeur analyzes a local software repository and produces a reproducible,
evidence-based audit report. It is designed for engineers who want an audit
trail they can verify by hand, not a chat answer they have to trust.

```
auditeur /path/to/repository
```

The result is a Markdown report under Auditeur's own state directory:

```
~/auditeur/<source-folder>/audit_<unix_timestamp>.md
```

## Why it exists

Most "AI code review" tools invert the problem: they ask a language model what
it thinks and present the answer as a finding. Auditeur does the opposite.

> **Deterministic evidence first. Local AI second.**

Auditeur collects what can be observed directly — filesystem structure, Git
state, manifests, dependency metadata, language statistics, tool output — and
turns it into typed *evidence*. A local model is then used for interpretation
only: correlating evidence, explaining a risk, proposing a recommendation.
Every AI-assisted finding must point at evidence that Auditeur itself has
verified against the repository. If the model cites something that is not
there, the citation is rejected.

Consequences of that principle:

- The model is never the source of truth. A finding is only as strong as its evidence.
- Repositories are untrusted input. Source code is data, never instruction.
- Audits are read-only and reproducible: same repository, same configuration, same report (modulo model non-determinism, which is recorded).
- Audit knowledge lives in versioned declarative definitions, not hard-coded heuristics.
- No prompt writing is required from the user. The user supplies a path; Auditeur decides what to inspect.

## Installation

### From a release

Every tagged release publishes prebuilt archives. Pick the target that matches
your machine — an archive is named `auditeur-<tag>-<target>.tar.gz`, or `.zip` on
Windows:

```
x86_64-unknown-linux-gnu    Linux, x86-64
aarch64-apple-darwin        macOS, Apple silicon
x86_64-apple-darwin         macOS, Intel
x86_64-pc-windows-msvc      Windows, x86-64 (zip)
```

```bash
TAG=v0.1.0
TARGET=aarch64-apple-darwin
BASE=https://github.com/afeldman/auditeur/releases/download

curl -fLO "$BASE/$TAG/auditeur-$TAG-$TARGET.tar.gz"
curl -fLO "$BASE/$TAG/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing     # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf "auditeur-$TAG-$TARGET.tar.gz"
sudo install "auditeur-$TAG-$TARGET/auditeur" /usr/local/bin/auditeur
```

Each archive carries the binary (`auditeur`, or `auditeur.exe` on Windows),
`README.md`, `LICENSE` and `NOTICE`. `auditeur --version` prints the release you
are running; see [Releases and versioning](#releases-and-versioning) for how a
release is cut.

### From source

Auditeur is an ordinary Cargo workspace:

```bash
cargo build --release
./target/release/auditeur doctor
```

Requirements: Rust 1.85 or newer. The MVP requires no native toolchains beyond
a Rust toolchain; a local OpenAI-compatible inference server is optional (an
audit completes deterministically without one).

## Setup

```bash
auditeur setup
```

An interactive terminal wizard (ratatui) writes a strongly typed TOML
configuration into `~/auditeur/config/`.

### The state directory

Auditeur keeps everything it owns in **one visible directory**, `~/auditeur` —
not a hidden `~/.auditeur`. Audit runs are artefacts a person is meant to read,
and configuration, history and logs should be easy to inspect, back up, archive
or delete:

```
~/auditeur/
├── config/           auditeur.toml, model.toml, audit.toml, definitions/
├── model/            local model artefacts
├── cache/            ast/, index/, analysis/ — created when first needed
├── runs/<run-id>/    manifest.json, findings.json, evidence.json
├── logs/             auditeur.log, auditeur.log.1, … (rolling)
└── <source-folder>/  audit_<unix_timestamp>.md
```

The root is chosen in this order, first match winning:

1. `--home <DIR>`;
2. a `.auditeur-project` file in the repository being audited, naming its state
   root;
3. `AUDITEUR_HOME`;
4. `$HOME/auditeur`.

A relative root is refused, because a run must not depend on the working
directory. `AUDITEUR_PROJECT_ROOT` is still honoured — it is the pre-1.0 name —
but it prints a note asking to rename it.

```
AUDITEUR_HOME=/srv/audit-state auditeur /path/to/repository
```

Directories are created **lazily**: `setup` writes the documented tree, the
logger creates its own directory, and the cache subdirectories appear when
something needs them. `auditeur doctor` describes the layout without creating
anything.

Auditeur never writes inside the audited repository. All of its own state lives
in the directory above.

### Logging

```toml
[logging]
level = "info"          # error | warn | info | debug | trace
file = "logs/auditeur.log"
max_size_mb = 20        # rotate when the active file would exceed this
max_files = 5           # rotated files kept: .1 … .5
```

The file path is relative to the state directory, and its parent *is* the log
directory — one setting decides where logs go, because two would drift apart.
Rotation is by size: `auditeur.log`, then `auditeur.log.1` … up to `max_files`.
The level can be raised for one process without touching the configuration:

```bash
auditeur --log-level debug audit .
```

Every record passes the same redaction that keeps credentials out of prompts,
findings and reports, so a secret that appears in a repository, an error message
or a configuration value does not reach the log either.

> **Audit runs are reproducible artefacts; logs are operational and debugging
> output and are not audit evidence.** Evidence lives only in
> `runs/<run-id>/{manifest,findings,evidence}.json`. Nothing in the audit model
> reads a log file, and no finding may be derived from one.

## Usage

```
auditeur [PATH]          audit PATH (default: the current directory)
auditeur audit <PATH>    explicit audit
auditeur setup           interactive configuration wizard
auditeur setup --non-interactive --source <PATH>   write defaults without a TTY
auditeur update          report audit definitions and model state
auditeur doctor          diagnose configuration, model, backend, toolchains
```

Flags, accepted before or after the subcommand:

```
--project <NAME>         project label, recorded in the report and configuration
--home <DIR>             state directory (default: $HOME/auditeur, or $AUDITEUR_HOME)
--log-level <LEVEL>      error|warn|info|debug|trace for this process only
--format <markdown|json> report format (sarif is declared, not implemented)
--fail-on <SEVERITY>     info|low|medium|high|critical (default: high)
--no-ai                  deterministic run; no model is consulted
--print                  also print the report on standard output
-q, --quiet              no progress; -v, -vv more detail on standard error
```

Progress and warnings go to standard error; results and the summary go to
standard output, so `auditeur -q . > summary.txt` is safe in a pipeline.

Exit codes: `0` clean, `1` findings at or above the configured failure
threshold, `2` usage/configuration/IO error.

A complete first run, without the wizard:

```bash
mkdir -p ~/auditeur && auditeur setup --non-interactive --source .
auditeur doctor
auditeur -v .
```

`AUDITEUR_HOME` sets the same directory via the environment, and a repository may
carry a `.auditeur-project` file naming its state root, so a subsequent
`auditeur` inside that repository finds its own configuration.

## Supported languages

Language support is adapter-based. Detection and metadata collection are
implemented for:

```
Rust  Go  Python  Node.js/JavaScript  Deno/TypeScript  C  C++  Julia  R  Lisp  Terraform/HCL
```

Rust, Go, Python and Node.js additionally have manifest parsing, dependency
extraction and test inventory in the MVP. Adding a language means implementing
one trait in `crates/auditeur-languages` — see DEVELOPMENT.md.

## Local AI

The inference layer is provider- and model-agnostic. The MVP ships one real
backend: an OpenAI-compatible HTTP client, which covers LM Studio, Ollama,
`llama.cpp --server`, vLLM and similar runtimes. In-process `llama.cpp`
inference with compile-time CPU/Metal/CUDA features is the next iteration.

The backend is configured in `~/auditeur/config/model.toml` — flat top-level
keys, nothing else:

```toml
backend = "openai_compatible"      # "mock" is the offline deterministic double
endpoint = "http://localhost:1234/v1"
model = "qwen/qwen2.5-coder-14b"   # as the server reports it
api_key_env = "AUDITEUR_API_KEY"   # optional; the key itself is never stored
enabled = true
request_timeout_secs = 120
max_output_tokens = 2048
temperature = 0.1                  # low: audit work rewards consistency
```

Each setting can be overridden for one process without touching the file —
`AUDITEUR_MODEL_ENDPOINT`, `AUDITEUR_MODEL_NAME`, `AUDITEUR_MODEL_BACKEND`,
`AUDITEUR_AI_ENABLED` — and `--no-ai` runs the deterministic audit whatever the
configuration says. An unconfigured model is not an error: the audit still runs,
and the run manifest records that AI-assisted analysis was skipped. `auditeur
doctor` reports what is actually in effect, including unknown keys and
unreachable endpoints.

The audit workflow generates its own structured tasks. Repository content is
passed to the model inside an explicitly fenced untrusted-data block, and model
output must be schema-valid JSON whose evidence references are re-verified
before use.

## Read-only guarantee

Audited repositories are strictly read-only. Auditeur does not modify, delete,
format, commit to, or otherwise alter the audited tree. This is enforced by
architecture (the repository crate exposes no write path, and the execution
boundary runs only allowlisted read-only commands with a scrubbed environment)
and verified by tests that fingerprint a fixture repository before and after a
full audit.

See [SECURITY.md](SECURITY.md) for the threat model and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Status

MVP — v0.1.0. Working and verified end to end:

- the pipeline: discovery → repository model → language analysis → planning →
  22 deterministic checks across 8 categories → model-assisted analysis →
  evidence verification → validated findings → Markdown/JSON report;
- the read-only boundary, fingerprint-checked before and after every run, on
  plain trees and on Git work trees, with the whole suite asserting that no
  audited repository changes;
- configuration precedence (defaults → TOML → `AUDITEUR_*` → flags), the
  interactive wizard, `doctor`, `update`, and the exit-code contract;
- the local model path, exercised against LM Studio: 5 of 5 audit tasks
  answered, each citation re-verified against evidence Auditeur supplied, and
  unverified claims kept but flagged as `unverified`.

Deliberately not there yet, and recorded rather than hidden:

- **Precise citations for absences.** A check that reports the absence of
  something (no licence, no tests) must cite the search that established it.
  Most do; where a check cites nothing, the pipeline attaches a search-level
  citation naming the repository root, and the run records how many times that
  was necessary. Those checks should cite precisely.
- **Deduplication.** A model-assisted finding can restate a deterministic one at
  the same location. The report distinguishes them by source, but a merge step
  is not implemented.
- **SARIF** is declared and refused, never faked. **HTML** is not started.
- **No external tool execution** by default: no `cargo clippy`, `go vet` or
  `pytest` is run unless configured, and the cache directories are created but
  unused by the current checks.
- **Test fixtures look like secrets.** The credential scan skips test
  *directories*, but a deliberate `AKIA...` example inside a `#[cfg(test)]`
  module in a source file is reported as a committed credential. Auditing
  Auditeur itself produces five such findings, in the fixtures that prove
  redaction works. The finding gives the exact location, so the reader can
  dismiss it; teaching the check to recognise test-module bodies without
  simultaneously hiding real credentials is not solved yet.
- **Model management** (download, checksum verification, pinning) and
  **in-process `llama.cpp`** with CPU/Metal/CUDA features are next, together
  with the roadmap in [DEVELOPMENT.md](DEVELOPMENT.md).

## Releases and versioning

The Git tag is the version. `v0.1.0` in Git is `version = "0.1.0"` in
`Cargo.toml` and the version `auditeur --version` prints; the release workflow
refuses to publish if the tag and the package version disagree, so a release can
never be mislabelled. Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and the notable changes of each release are recorded in [CHANGELOG.md](CHANGELOG.md).

Cutting a release is one tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions then does everything else, with no manual upload step:

1. run `cargo fmt --all -- --check`, `cargo check --workspace --all-targets`,
   `cargo clippy --workspace --all-targets -- -D warnings` and
   `cargo test --workspace` — a red gate means no release;
2. build each supported target with `cargo build --release --locked`;
3. package one archive per target and a `SHA256SUMS` over them;
4. create the GitHub release for the tag, with notes taken from the matching
   `CHANGELOG.md` section and the archives attached.

A release needs three files to be present in the repository, and the workflow
fails with a named error rather than inventing any of them: `Cargo.lock` (the
release build is `--locked`, so the dependency graph of a release is the one that
was reviewed), and `LICENSE` and `NOTICE` (every archive must carry them).

Archives are built deterministically — fixed timestamps, fixed file modes, one
top-level directory per archive — so the same tag produces byte-identical
archives. They contain the binary and `README.md`, `LICENSE` and `NOTICE`, and
nothing else: Auditeur's local state under `~/auditeur` is never packaged.
`aarch64-unknown-linux-gnu` is not built yet; it needs a cross linker that the
other targets do not, so it is deliberately left out until that is set up.

The packaging, verification and note-generation steps are plain Python with no
dependencies, so a release can be rehearsed before a tag exists. Put the built
binaries in `bins/bin-<target>/`, one directory per target, then:

```bash
python3 .github/scripts/release_artifacts.py package --tag v0.1.0 --bins-dir bins --out-dir dist
python3 .github/scripts/release_artifacts.py verify  --tag v0.1.0 --bins-dir bins --out-dir dist
python3 .github/scripts/release_notes.py --tag v0.1.0 --version 0.1.0 \
  --dist-dir dist --repository afeldman/auditeur --out release-notes.md
```

`verify` re-reads `dist/` from disk and fails on any deviation: an unexpected or
missing file, a member that does not match the file it was packaged from, a
missing executable bit, a checksum that does not agree, or a member that looks
like local Auditeur state.

## License

MIT OR Apache-2.0, at your option. Both licence texts are in [LICENSE](LICENSE);
[NOTICE](NOTICE) carries the attribution. Every release archive contains a copy
of both.
