# Changelog

All notable changes to Auditeur will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-10-02

A release-tooling release. No production code changed since `0.1.0`: the audit
engine, the evidence model, the read-only boundary and the command-line surface
are untouched. What follows is how a release is cut, and how the test suite
behaves away from macOS.

### Added

- `cargo-release` as the release driver, configured in
  `[workspace.metadata.release]`. One command moves the workspace version,
  updates `Cargo.lock`, commits and creates the signed annotated tag, so the tag
  and the version cannot drift apart. It is a tool rather than a dependency,
  and it does not publish: the workflow only builds what was already tagged.

### Changed

- The release workflow validates the tag against the **shared workspace version**
  read from `cargo metadata`, instead of one package's version, and refuses to
  build when the workspace resolves to more than one version. The failure message
  now names the cause and the remedy rather than reading as if the workflow
  modified the manifest — it never does, and it still creates no commit and moves
  no tag.

### Fixed

- Three test defects that made the suite pass on macOS and fail on Linux. None of
  them was a product defect; in each case the test asserted a filesystem
  behaviour rather than the property it was written for.
  - The CLI test harness copied fixtures without their modification times. On
    macOS `fs::copy` inherits the source's time, on Linux it does not, so two
    sandboxes of the same fixture were metadata-identical on one platform and
    not the other — and the test comparing the two command spellings compares
    two sandboxes. The harness now restores the times it copied.
  - The Git read-only probe test raced Git's own automatic maintenance, which
    recent versions start after `git commit` and which briefly holds
    `.git/objects/maintenance.lock`. The test then reported the end of that pass
    as a change the probe had made. Probing itself writes nothing: run against
    the six read-only Git invocations the probe performs, not one of the 40
    entries under `.git` changes.
  - The fingerprint test expected two consecutive writes to receive different
    modification times. That is a property of the filesystem's timestamp
    granularity, not of the fingerprint walk — it holds on APFS and usually does
    not on Linux's coarse clock. The test now sets the new time explicitly, and
    still asserts exactly what it asserted before.

### Known limitations

- **No GitHub release exists for any version yet.** The release pipeline has
  never completed a full run: every attempt so far stopped in the quality gate,
  and the platform archives have therefore never been built.
- `v0.1.1` and `v0.1.2` are published tags whose commits still carry workspace
  version `0.1.0`. They are left in place and cannot produce a release. The next
  version that can be built is this one.

## [0.1.0] - 2026-10-02

First release. Auditeur is a local, evidence-driven software auditor: it
collects what can be observed about a repository, and a local model is used for
interpretation only.

### Added

- Rust workspace with ten crates and an acyclic dependency graph:
  `auditeur-model`, `auditeur-config`, `auditeur-repository`,
  `auditeur-languages`, `auditeur-inference`, `auditeur-audit`,
  `auditeur-report`, `auditeur-logging`, `auditeur-tui` and `auditeur-cli`.
- The `auditeur` command-line program with the subcommands `audit`, `setup`,
  `doctor` and `update`, a documented exit-code contract (`0` clean, `1`
  findings at or above the threshold, `2` usage/configuration/IO error) and
  results on standard output separated from progress on standard error.
- The audit pipeline: discovery → repository model → language analysis →
  planning → 22 deterministic checks across 8 categories → model-assisted
  analysis → evidence verification → validated findings → report.
- Language detection for Rust, Go, Python, Node.js/JavaScript, Deno/TypeScript,
  C, C++, Julia, R, Lisp and Terraform/HCL, with manifest parsing, dependency
  extraction and test inventory for Rust, Go, Python and Node.js.
- A read-only repository boundary: the repository crate exposes no write path,
  and the execution boundary runs only allowlisted read-only commands with a
  scrubbed environment. Verified by tests that fingerprint a fixture repository
  before and after a full audit, on plain trees and on Git work trees.
- Typed TOML configuration in `config/auditeur.toml`, `config/model.toml` and
  `config/audit.toml`, with the precedence compiled defaults → file →
  `AUDITEUR_*` environment variables → command-line flags.
- An interactive `setup` wizard (ratatui) and a non-interactive
  `setup --non-interactive` path for machines without a TTY.
- One visible state directory for everything Auditeur owns — `~/auditeur` by
  default, chosen by `--home`, a `.auditeur-project` file, `AUDITEUR_HOME` or
  `$HOME` — with the documented layout `config/ model/ cache/ runs/ logs/` and
  lazy creation of subdirectories.
- Rolling, size-based application logging with the same redaction that keeps
  credentials out of prompts, findings and reports applied to every log record.
- An OpenAI-compatible HTTP inference backend for LM Studio, Ollama,
  `llama.cpp --server` and vLLM; deliberate `--no-ai` mode and a deterministic
  mock backend for runs without a model.
- Markdown audit reports and machine-readable run artifacts
  (`runs/<run-id>/manifest.json`, `findings.json`, `evidence.json`).

### Security

- Audited repositories are never written to, and Auditeur refuses to start if
  its state root would lie inside the tree it is auditing.
- Repository content reaches the model inside an explicitly fenced untrusted-data
  block, and model output must be schema-valid JSON whose evidence references are
  re-verified before use. A citation the model cannot support is kept but
  flagged `unverified`; it is never presented as verified.
- Secrets are redacted before they reach a prompt, a finding, a report or a log
  file.

### Known limitations

- SARIF output is declared and refused rather than faked; HTML output is not
  implemented.
- Checks that report the *absence* of something fall back to a search-level
  citation naming the repository root, and the run records how often that was
  necessary.
- No external analysis tools (`cargo clippy`, `go vet`, `pytest`) are executed
  unless configured.
- Credential scanning skips test directories but not a `#[cfg(test)]` module
  inside a source file, so auditing Auditeur's own tree reports the deliberately
  fake credentials in its fixtures. Each finding names its exact location.
