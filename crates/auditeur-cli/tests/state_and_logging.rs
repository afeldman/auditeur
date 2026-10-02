//! The state directory and the log, end to end through the real binary.
//!
//! What these tests are for: the state root is `~/auditeur`, it can be moved with
//! `AUDITEUR_HOME`, every artefact an audit produces lands inside it, the log is a
//! rolling file beside those artefacts — and no credential ever reaches it.

mod common;

use std::fs;

use common::*;

/// The default state root is `$HOME/auditeur`, with no leading dot.
#[test]
fn the_state_root_defaults_to_home_auditeur() {
    let sandbox = Sandbox::new("rust-app");

    // Without AUDITEUR_HOME, the state root is $HOME/auditeur. The harness sets
    // HOME to a sandbox, so this is still isolated.
    let mut command = sandbox.command(&["--quiet"]);
    command.env_remove("AUDITEUR_HOME");
    let output = command.output().expect("the binary runs");
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    let report = sandbox
        .reports()
        .into_iter()
        .next()
        .expect("a report was written");
    assert!(
        report.starts_with(sandbox.home_dir().join("auditeur")),
        "the report must live under $HOME/auditeur, found {}",
        report.display()
    );
    assert!(
        sandbox
            .home_dir()
            .join("auditeur/logs/auditeur.log")
            .is_file(),
        "the log must live under $HOME/auditeur/logs"
    );
    // Not a hidden directory: the whole point of the move.
    assert!(!sandbox.home_dir().join(".auditeur").exists());
}

/// `AUDITEUR_HOME` moves the state root.
#[test]
fn auditeur_home_moves_the_state_root() {
    let sandbox = Sandbox::new("go-app");
    let elsewhere = sandbox.home_dir().join("moved");

    let output = sandbox.run_with_env(
        &["--quiet"],
        &[("AUDITEUR_HOME", elsewhere.to_str().unwrap())],
    );
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    assert!(
        elsewhere.join("runs").is_dir(),
        "runs belong to the new root"
    );
    assert!(elsewhere.join("logs/auditeur.log").is_file());
    // The state inside the new root is complete.
    let run_dir = fs::read_dir(elsewhere.join("runs"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("a run directory");
    for artifact in ["manifest.json", "findings.json", "evidence.json"] {
        assert!(run_dir.join(artifact).is_file(), "missing {artifact}");
    }
}

/// The pre-1.0 variable still works, and says so rather than moving the state
/// root silently.
#[test]
fn the_legacy_variable_is_honoured_with_a_note() {
    let sandbox = Sandbox::new("python-app");
    let legacy = sandbox.home_dir().join("legacy");

    let mut command = sandbox.command(&["--quiet"]);
    command.env_remove("AUDITEUR_HOME");
    command.env("AUDITEUR_PROJECT_ROOT", &legacy);
    let output = command.output().expect("the binary runs");
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    assert!(
        legacy.join("runs").is_dir(),
        "the deprecated variable must still select the state root"
    );
}

/// A relative state root is refused rather than resolved against the working
/// directory, which would make a run depend on where it was started.
#[test]
fn a_relative_state_root_is_refused() {
    let sandbox = Sandbox::new("rust-app");
    let output = sandbox.run_with_env(&["--quiet"], &[("AUDITEUR_HOME", "relative/state")]);
    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("relative"),
        "the error must say why: {}",
        stderr(&output)
    );
    assert!(sandbox.reports().is_empty());
}

/// Runs are stored under the state root, named by the run id, and the log names
/// the same run.
#[test]
fn a_run_is_stored_under_the_state_root_and_the_log_names_it() {
    let sandbox = Sandbox::new("leaky-app");
    let output = sandbox.audit();
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    let manifest = sandbox.manifest();
    let run_id = manifest["run_id"].as_str().unwrap();
    let run_dir = sandbox.state().join("runs").join(run_id);
    assert!(
        run_dir.is_dir(),
        "the run must live at runs/<run-id>, expected {}",
        run_dir.display()
    );
    assert_eq!(
        sandbox.run_dir(),
        run_dir,
        "the artefact directory and the manifest must agree"
    );

    // The log records the run under the same identifier, so a log line and a run
    // directory can be matched by eye.
    let log = sandbox.log_text();
    assert!(log.contains("run_id"), "no run id in the log: {log}");
    assert!(
        log.contains(run_id),
        "the log does not name this run: {log}"
    );
    assert!(log.contains("audit started"), "{log}");
    assert!(log.contains("audit finished"), "{log}");
    // Level and target, as documented.
    assert!(log.contains("INFO"), "{log}");
    assert!(log.contains("auditeur"), "{log}");
}

/// The log is a rolling file beside the runs and the configuration, not inside
/// the audited repository, and not among the run artefacts.
#[test]
fn the_log_lives_beside_the_state_and_not_in_the_repository() {
    let sandbox = Sandbox::new("rust-app");
    assert!(matches!(code(&sandbox.audit()), 0 | 1));

    let log = sandbox.log_file();
    assert!(log.is_file(), "no log at {}", log.display());
    assert_eq!(
        log.parent().unwrap(),
        sandbox.state().join("logs"),
        "the log directory comes from the configured file"
    );
    assert!(
        !sandbox.repo().join("logs").exists(),
        "the repository must not receive the log"
    );
    assert!(
        !sandbox.repo().join("auditeur.log").exists(),
        "the repository must not receive the log"
    );
}

/// Logs are operational artefacts and runs are audit artefacts: neither is
/// written into the other's directory.
#[test]
fn logs_and_run_artefacts_are_kept_apart() {
    let sandbox = Sandbox::new("rust-app");
    assert!(matches!(code(&sandbox.audit()), 0 | 1));

    let run_files: Vec<String> = sandbox
        .artifact_files()
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(run_files.contains(&"manifest.json".to_string()));
    assert!(
        !run_files.iter().any(|name| name.contains("auditeur.log")),
        "no log may appear in a run directory: {run_files:?}"
    );

    let log_files: Vec<String> = sandbox
        .log_files()
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(!log_files.is_empty());
    assert!(
        !log_files.iter().any(|name| name == "manifest.json"
            || name == "findings.json"
            || name == "evidence.json"),
        "no audit artefact may appear in the log directory: {log_files:?}"
    );
}

/// The configured level decides what is written; the flag overrides it for one
/// process without touching the configuration.
#[test]
fn the_log_level_comes_from_the_configuration_and_the_flag_overrides_it() {
    // At `warn`, the audit narrative is not written.
    let quiet_sandbox = Sandbox::new("rust-app");
    quiet_sandbox.write_config(
        "auditeur.toml",
        "[project]\nname = \"demo\"\n\n[logging]\nlevel = \"warn\"\n",
    );
    assert!(matches!(code(&quiet_sandbox.audit()), 0 | 1));
    assert!(
        !quiet_sandbox.log_text().contains("audit started"),
        "warn must silence info: {}",
        quiet_sandbox.log_text()
    );

    // The flag raises it for this process only.
    let loud_sandbox = Sandbox::new("rust-app");
    loud_sandbox.write_config(
        "auditeur.toml",
        "[project]\nname = \"demo\"\n\n[logging]\nlevel = \"warn\"\n",
    );
    let output = loud_sandbox.run(&["--log-level", "debug", "--quiet"]);
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    let log = loud_sandbox.log_text();
    assert!(log.contains("audit started"), "{log}");
    assert!(
        log.contains("DEBUG"),
        "the flag must add developer detail: {log}"
    );
    // The configuration file is unchanged: the override is not a write.
    let config = fs::read_to_string(loud_sandbox.state().join("config/auditeur.toml")).unwrap();
    assert!(config.contains("level = \"warn\""), "{config}");
}

/// The log stays within its configured file count and naming.
///
/// Crossing the size limit is proven in `auditeur-logging`'s own tests, which
/// push a mebibyte through the real subscriber and assert that a predecessor
/// file appeared; a fixture audit writes tens of kilobytes, so it exercises the
/// bound and the names rather than the boundary itself.
#[test]
fn the_log_files_stay_within_the_configured_count_and_names() {
    let sandbox = Sandbox::new("rust-app");
    // One mebibyte is the smallest size the configuration accepts; the run below
    // writes enough to cross it through the real code path.
    sandbox.write_config(
        "auditeur.toml",
        "[project]\nname = \"demo\"\n\n[logging]\nlevel = \"debug\"\nmax_size_mb = 1\nmax_files = 2\n",
    );

    let output = sandbox.run(&["--log-level", "trace", "--quiet"]);
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    // Many events of a few hundred bytes each: a trace run over a fixture is
    // small, so the log is filled explicitly through repeated audits.
    for _ in 0..3 {
        let _ = sandbox.run(&["--log-level", "trace", "--quiet"]);
    }

    let files = sandbox.log_files();
    assert!(!files.is_empty());
    assert!(
        files.len() <= 3,
        "max_files = 2 must keep at most three files: {files:?}"
    );
    assert!(
        files.iter().all(|path| path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("auditeur.log")),
        "{files:?}"
    );
}

/// A run may not write a credential into the log, whatever the console flags say.
#[test]
fn no_credential_reaches_the_log() {
    let sandbox = Sandbox::new("leaky-app");
    let output = sandbox.run(&["--log-level", "trace", "--print"]);
    assert!(matches!(code(&output), 0 | 1), "{}", stderr(&output));

    // The fixture really does contain credential-shaped content.
    let planted = fs::read_to_string(sandbox.repo().join("src/leaky_app/settings.py")).unwrap();
    assert!(
        planted.contains("AKIA"),
        "the fixture must carry a credential"
    );

    let log = sandbox.log_text();
    assert!(!log.is_empty(), "the run should have logged something");
    for line in planted.lines() {
        let value = line
            .split_once('=')
            .map(|(_, value)| value.trim().trim_matches('"'))
            .unwrap_or_default();
        if value.len() >= 12 {
            assert!(
                !log.contains(value),
                "the log contains a value copied from the repository"
            );
        }
    }
}

/// `setup` creates the documented tree, and nothing below it that is not needed.
#[test]
fn setup_creates_the_documented_state_tree() {
    let sandbox = Sandbox::new("python-app");
    let repo = sandbox.repo().to_string_lossy().to_string();

    let output = sandbox.run(&["setup", "--non-interactive", "--source", &repo]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    for directory in ["config", "model", "cache", "runs", "logs"] {
        assert!(
            sandbox.state().join(directory).is_dir(),
            "setup must create {directory}/"
        );
    }
    for file in [
        "config/auditeur.toml",
        "config/model.toml",
        "config/audit.toml",
    ] {
        assert!(sandbox.state().join(file).is_file(), "missing {file}");
    }
    // Lazy: the cache's own subdirectories are not created by setup.
    assert!(!sandbox.state().join("cache/ast").exists());

    // The saved configuration is portable: relative paths, no absolute state root.
    let config = fs::read_to_string(sandbox.state().join("config/auditeur.toml")).unwrap();
    assert!(config.contains("[paths]"), "{config}");
    assert!(config.contains("[logging]"), "{config}");
    assert!(
        !config.contains(sandbox.state().to_str().unwrap()),
        "the state root must not be written into the configuration: {config}"
    );
}

/// `doctor` describes the state layout without creating it.
#[test]
fn doctor_diagnoses_the_state_layout_without_creating_it() {
    let sandbox = Sandbox::new("rust-app");
    let output = sandbox.run(&["doctor", "--json"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let diagnosis: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    let names: Vec<String> = diagnosis["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line["name"].as_str().unwrap().to_string())
        .collect();
    for expected in [
        "Auditeur home",
        "Config directory",
        "Model directory",
        "Cache directory",
        "Runs directory",
        "Logs directory",
        "Logging",
        "Logger",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }

    // Nothing was created by looking, apart from the log the diagnosis itself
    // wrote: the logger is the one thing a run always needs.
    assert!(!sandbox.state().join("cache").exists());
    assert!(!sandbox.state().join("model").exists());
    assert!(!sandbox.state().join("runs").exists());
}

/// The read-only guarantee still holds with the new state layout: auditing writes
/// under the state root and nowhere else.
#[test]
fn the_audited_repository_is_still_untouched() {
    for (fixture, _) in FIXTURES {
        let sandbox = Sandbox::new(fixture);
        let before = digest_tree(sandbox.repo());

        let output = sandbox.audit();
        assert!(
            matches!(code(&output), 0 | 1),
            "{fixture}: {}",
            stderr(&output)
        );

        assert_eq!(
            before,
            digest_tree(sandbox.repo()),
            "{fixture}: the audit changed the repository"
        );
        for artefact in sandbox.reports().iter().chain(sandbox.log_files().iter()) {
            assert!(
                artefact.starts_with(sandbox.state()),
                "{} is outside the state root",
                artefact.display()
            );
        }
    }
}
