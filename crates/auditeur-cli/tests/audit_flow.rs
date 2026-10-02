//! End-to-end tests of the audit workflow through the real binary.
//!
//! These tests assert the contract the design promises, not the implementation:
//! where output lands, what the exit code means, that a finding can be verified
//! by a human, and that a secret never survives redaction.

mod common;

use common::*;

/// The report lands in the project directory, in a folder named after the
/// audited repository, and a machine-readable run record is written beside it.
#[test]
fn the_default_command_writes_a_report_and_a_run_record() {
    let sandbox = Sandbox::new("rust-app");
    let output = sandbox.audit();

    let code = code(&output);
    assert!(
        code == 0 || code == 1,
        "unexpected exit code {code}: {}",
        stderr(&output)
    );

    let report = sandbox.report();
    assert_eq!(
        report.parent().unwrap().file_name().unwrap(),
        "rust-app",
        "the report belongs in a folder named after the audited repository"
    );
    let name = report.file_name().unwrap().to_string_lossy().to_string();
    assert!(
        name.starts_with("audit_") && name.ends_with(".md"),
        "{name}"
    );

    // The report lives outside the audited repository.
    assert!(report.starts_with(sandbox.state()));

    let run_dir = sandbox.run_dir();
    for artifact in ["manifest.json", "findings.json", "evidence.json"] {
        assert!(
            run_dir.join(artifact).is_file(),
            "missing {artifact} in {}",
            run_dir.display()
        );
    }

    // The manifest is the reproducibility record: every field below is something
    // a later reader needs in order to make sense of the run.
    let manifest = sandbox.manifest();
    assert_eq!(manifest["auditeur_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["audit_schema_version"], "1.0.0");
    assert!(!manifest["run_id"].as_str().unwrap().is_empty());
    assert!(manifest["unix_timestamp"].as_i64().unwrap() > 1_600_000_000);
    assert!(manifest["files_inspected"].as_u64().unwrap() > 0);
    assert!(manifest["counts"]["pass"].as_u64().unwrap() > 0);
    assert!(
        manifest["limits"].is_object(),
        "the resource policy is recorded"
    );
    assert_eq!(
        manifest["report_path"].as_str().unwrap(),
        report.to_str().unwrap()
    );
    assert_eq!(
        manifest["repository"]["fingerprint"]["digest"]
            .as_str()
            .unwrap()
            .len(),
        64,
        "the repository fingerprint is a SHA-256 digest"
    );
    assert!(
        manifest["started_at"].as_str().unwrap().contains('T'),
        "timestamps are RFC 3339"
    );
}

/// Both spellings of the command audit the same tree and describe it identically.
#[test]
fn the_explicit_form_describes_the_same_repository_as_the_default_form() {
    let bare = Sandbox::new("go-app");
    let bare_output = bare.audit();
    assert!(matches!(code(&bare_output), 0 | 1));

    let explicit = Sandbox::new("go-app");
    let path = explicit.repo().to_string_lossy().to_string();
    let explicit_output = explicit.run(&["audit", &path]);
    assert!(matches!(code(&explicit_output), 0 | 1));

    assert_eq!(
        bare.manifest()["repository"]["fingerprint"]["digest"],
        explicit.manifest()["repository"]["fingerprint"]["digest"],
        "the same tree must produce the same fingerprint"
    );
    assert_eq!(
        bare.manifest()["counts"],
        explicit.manifest()["counts"],
        "the same tree must produce the same findings"
    );
}

/// Every fixture is named in the manifest, which is what the language adapters
/// are for. A fixture whose detection broke would silently audit almost nothing.
#[test]
fn every_fixture_is_detected_as_its_own_language() {
    for (fixture, expected) in FIXTURES {
        let sandbox = Sandbox::new(fixture);
        let output = sandbox.audit();
        assert!(
            matches!(code(&output), 0 | 1),
            "{fixture}: exit code {}: {}",
            code(&output),
            stderr(&output)
        );

        let languages = sandbox.manifest()["detected_languages"]
            .as_array()
            .expect("detected_languages is an array")
            .iter()
            .map(|value| value.as_str().expect("a language id").to_string())
            .collect::<Vec<_>>();

        assert!(
            languages.contains(&expected.to_string()),
            "{fixture}: expected {expected}, got {languages:?}"
        );

        // And the report says so too: detection that only reaches the manifest
        // would leave the human-readable document incomplete.
        let report = sandbox.report_text();
        assert!(
            report.contains("## Detected languages"),
            "{fixture}: the report has no language section"
        );
    }
}

/// A violation of a declared severity breaches the threshold; the same run does
/// not breach a higher one. This is the exit-code contract in one test.
#[test]
fn the_failure_threshold_decides_the_exit_code() {
    let strict = Sandbox::new("leaky-app");
    let by_severity = strict.run(&["--fail-on", "high"]);
    assert_eq!(
        code(&by_severity),
        1,
        "a high-severity violation must fail a high threshold: {}",
        stdout(&by_severity)
    );

    let relaxed = Sandbox::new("leaky-app");
    let by_critical = relaxed.run(&["--fail-on", "critical"]);
    let critical = relaxed
        .findings()
        .iter()
        .any(|finding| finding["severity"] == "critical");
    assert!(
        !critical,
        "the fixture is assumed to have no critical finding; the test needs revisiting"
    );
    assert_eq!(
        code(&by_critical),
        0,
        "no critical finding exists, so a critical threshold must pass"
    );
    // The findings are still reported, they simply do not gate the exit code.
    assert!(!relaxed.findings().is_empty());
}

/// Every violation must be checkable by hand: it cites evidence, and the path in
/// that evidence exists in the audited repository.
#[test]
fn every_violation_cites_evidence_that_resolves_to_a_real_file() {
    let sandbox = Sandbox::new("leaky-app");
    let output = sandbox.audit();
    assert!(matches!(code(&output), 0 | 1));

    let evidence = sandbox.evidence();
    let findings = sandbox.findings();

    let mut violations = 0;
    for finding in &findings {
        let status = finding["status"].as_str().unwrap();
        if status != "FAIL" && status != "WARN" {
            continue;
        }
        violations += 1;

        let references = finding["evidence"].as_array().unwrap();
        assert!(
            !references.is_empty(),
            "{} ({}) is a violation with no evidence",
            finding["title"],
            finding["id"]
        );

        // Resolve each reference against the evidence store, exactly as a reader
        // would have to.
        for reference in references {
            let id = reference["evidence_id"].as_str().unwrap();
            let item = evidence
                .iter()
                .find(|item| item["id"] == id)
                .unwrap_or_else(|| panic!("finding {id} cites evidence that is not in the store"));

            let location = &item["location"];
            let path = location["path"]
                .as_str()
                .or_else(|| location.get("file").and_then(|value| value.as_str()))
                .unwrap_or_else(|| panic!("evidence {id} has no path: {location}"));

            // A path that escapes the repository would be a security defect, not
            // a reporting detail.
            assert!(
                !path.starts_with('/') && !path.contains(".."),
                "evidence path {path} must be repository-relative"
            );
            assert!(
                sandbox.repo().join(path).exists(),
                "evidence path {path} does not exist in the audited repository"
            );
        }
    }

    assert!(violations > 0, "the fixture should produce violations");
}

/// The report is honest about what it could not do.
#[test]
fn the_report_states_its_limitations() {
    let sandbox = Sandbox::new("rust-app");
    assert!(matches!(code(&sandbox.audit()), 0 | 1));

    let report = sandbox.report_text();
    for section in [
        "## Executive summary",
        "## Repository information",
        "## Environment",
        "## Detected languages",
        "## Audit scope",
        "## Methodology",
        "## Findings",
        "## Limitations",
        "## Reproducibility",
    ] {
        assert!(report.contains(section), "the report lacks {section}");
    }

    assert!(
        !report.contains("overall score") || report.contains("No overall score"),
        "the report must not present an aggregate score"
    );
    assert!(
        !sandbox.manifest()["limitations"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a run over a small fixture still has limitations to declare"
    );
}

/// Redaction is a promise about every artefact, not just the report.
#[test]
fn no_secret_survives_into_any_artefact() {
    let sandbox = Sandbox::new("leaky-app");
    assert!(matches!(code(&sandbox.audit()), 0 | 1));

    // The fixture's values must appear in the repository verbatim, otherwise this
    // test proves nothing.
    let planted =
        std::fs::read_to_string(sandbox.repo().join("src/leaky_app/settings.py")).unwrap();
    for secret in ["AKIAIOSFODNN7EXAMPLE", "correct-horse-battery-staple"] {
        assert!(
            planted.contains(secret),
            "the fixture must contain {secret}"
        );
    }

    let mut artefacts: Vec<(String, String)> = vec![("report".to_string(), sandbox.report_text())];
    for file in sandbox.artifact_files() {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        artefacts.push((name, std::fs::read_to_string(&file).unwrap()));
    }

    for (name, text) in &artefacts {
        for secret in ["AKIAIOSFODNN7EXAMPLE", "correct-horse-battery-staple"] {
            assert!(
                !text.contains(secret),
                "{name} contains the raw value {secret}"
            );
        }
    }

    // The evidence still has to be useful: the location is there, redacted value.
    let report = sandbox.report_text();
    assert!(
        report.contains("settings.py"),
        "the credential's location must survive redaction"
    );
    assert!(
        report.contains("[REDACTED:aws-key-id]") || report.contains("REDACTED"),
        "redaction must be visible rather than silent"
    );
}

/// A run with a model configured but unreachable degrades: it still audits, it
/// still writes a report, and it records what it could not do.
#[test]
fn an_unreachable_model_degrades_the_run_instead_of_aborting_it() {
    let sandbox = Sandbox::new("rust-app");
    sandbox.write_config(
        "model.toml",
        "backend = \"openai_compatible\"\n\
         endpoint = \"http://127.0.0.1:9/v1\"\n\
         model = \"qwen/qwen2.5-coder-14b\"\n\
         enabled = true\n\
         request_timeout_secs = 5\n",
    );

    let output = sandbox.audit();
    let code = code(&output);
    assert!(
        code == 0 || code == 1,
        "an unreachable server must not abort the audit; exit code {code}: {}",
        stderr(&output)
    );

    let manifest = sandbox.manifest();
    assert_eq!(
        manifest["ai_enabled"], true,
        "the run was asked to use a model and should say so"
    );

    let limitations = manifest["limitations"].as_array().unwrap();
    let text = serde_json::to_string(limitations).unwrap().to_lowercase();
    assert!(
        !limitations.is_empty(),
        "the failure to reach the model must be recorded"
    );
    assert!(
        text.contains("model") || text.contains("backend") || text.contains("inference"),
        "no limitation explains the model problem: {text}"
    );

    // The deterministic work is unaffected: evidence and findings still exist.
    assert!(!sandbox.findings().is_empty());
    assert!(!sandbox.evidence().is_empty());
}

/// `--no-ai` is the explicit promise that no model is consulted, and the manifest
/// records the run as such.
#[test]
fn no_ai_produces_a_deterministic_run() {
    let sandbox = Sandbox::new("rust-app");
    sandbox.write_config(
        "model.toml",
        "endpoint = \"http://127.0.0.1:9/v1\"\nmodel = \"qwen/qwen2.5-coder-14b\"\n",
    );

    let output = sandbox.run(&["--no-ai"]);
    assert!(matches!(code(&output), 0 | 1));
    assert_eq!(sandbox.manifest()["ai_enabled"], false);
    assert_eq!(sandbox.manifest()["model"]["name"], "none");
}

/// The JSON renderer writes a machine-readable report, and it describes the same
/// run as the Markdown one.
#[test]
fn the_json_report_is_available_and_consistent() {
    let sandbox = Sandbox::new("rust-app");
    let output = sandbox.run(&["--format", "json"]);
    assert!(matches!(code(&output), 0 | 1));

    let report = sandbox.report();
    assert!(
        report.to_string_lossy().ends_with(".json"),
        "expected a JSON report, got {}",
        report.display()
    );

    let document = read_json(&report);
    assert_eq!(document["audit_schema_version"], "1.0.0");
    assert!(!document["findings"].as_array().unwrap().is_empty());
    assert_eq!(
        document["run_id"],
        sandbox.manifest()["run_id"],
        "both documents describe the same run"
    );
}

/// SARIF is declared, and asking for it must fail loudly rather than emit a
/// document that pretends to be SARIF.
#[test]
fn sarif_is_refused_rather_than_faked() {
    let sandbox = Sandbox::new("rust-app");
    let output = sandbox.run(&["--format", "sarif"]);
    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(
        stderr(&output).to_lowercase().contains("sarif"),
        "the error must name the format: {}",
        stderr(&output)
    );
    assert!(sandbox.reports().is_empty(), "no report may be written");
}

/// Progress goes to standard error, so a pipeline can consume standard output.
#[test]
fn progress_never_pollutes_standard_output() {
    // Quiet silences progress and warnings, not the result.
    let sandbox = Sandbox::new("rust-app");
    let quiet = sandbox.run(&["--quiet"]);
    assert!(matches!(code(&quiet), 0 | 1));
    assert_eq!(
        stderr(&quiet).trim(),
        "",
        "quiet mode must print no progress"
    );
    assert!(
        stdout(&quiet).contains("finding(s)"),
        "the summary is a result and belongs on stdout: {}",
        stdout(&quiet)
    );

    // Verbose reports stages — on stderr, so a pipeline reading stdout is
    // unaffected by how chatty the run is.
    let verbose_sandbox = Sandbox::new("rust-app");
    let verbose = verbose_sandbox.run(&["-v"]);
    assert!(matches!(code(&verbose), 0 | 1));
    assert!(
        stderr(&verbose).contains("repository discovery"),
        "verbosity must report stages on stderr: {}",
        stderr(&verbose)
    );
    assert!(
        !stdout(&verbose).contains("repository discovery"),
        "progress must never reach stdout: {}",
        stdout(&verbose)
    );
}

/// `setup --non-interactive`, then `doctor`, then an audit: the configuration the
/// wizard writes is the configuration the rest of the tool uses.
#[test]
fn configure_then_diagnose_then_audit() {
    let sandbox = Sandbox::new("python-app");
    let repo = sandbox.repo().to_string_lossy().to_string();

    let setup = sandbox.run(&["setup", "--non-interactive", "--source", &repo]);
    assert_eq!(code(&setup), 0, "{}", stderr(&setup));
    for file in [
        "config/auditeur.toml",
        "config/model.toml",
        "config/audit.toml",
    ] {
        assert!(
            sandbox.state().join(file).is_file(),
            "setup did not write {file}"
        );
    }

    // A second setup must refuse to overwrite without --force.
    let again = sandbox.run(&["setup", "--non-interactive", "--source", &repo]);
    assert_eq!(code(&again), 2);
    assert!(stderr(&again).contains("--force"));

    let doctor = sandbox.run(&["doctor", "--json"]);
    assert_eq!(code(&doctor), 0, "{}", stderr(&doctor));
    let diagnosis: serde_json::Value = serde_json::from_str(stdout(&doctor).trim()).unwrap();
    assert!(
        diagnosis["diagnostics"].as_array().unwrap().len() > 5,
        "doctor should check more than a handful of things"
    );
    assert!(
        !diagnosis["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line["required"] == true && line["status"] != "ok"),
        "a configured project must not fail a required check"
    );
    assert!(
        !diagnosis["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line["name"] == "Model" && line["status"] == "ok"),
        "no model is selected, so the model line must not claim otherwise"
    );

    // The audit runs with no path: it uses the configured repository.
    let inside = sandbox.run(&["--quiet"]);
    assert!(matches!(code(&inside), 0 | 1), "{}", stderr(&inside));
    assert!(sandbox.report().is_file());
}

/// An unknown configuration key is a warning, not a failure: a newer file must
/// stay readable by an older binary.
#[test]
fn an_unknown_configuration_key_is_reported_not_fatal() {
    let sandbox = Sandbox::new("rust-app");
    sandbox.write_config(
        "auditeur.toml",
        "[project]\nname = \"demo\"\n\n[future]\nexperimental = true\n",
    );

    let output = sandbox.run(&["doctor"]);
    assert_eq!(code(&output), 0, "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("future") || text.contains("unknown"),
        "doctor should name the unrecognised key: {text}"
    );

    // And the audit still runs.
    let audit = sandbox.audit();
    assert!(matches!(code(&audit), 0 | 1));
}
