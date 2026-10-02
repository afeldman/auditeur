# Changelog

All notable changes to Auditeur will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
