//! Dependency checks, derived from manifests already in the repository.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Requirement strings that do not constrain a version.
const UNPINNED_REQUIREMENTS: &[&str] = &["", "*", "latest", "any"];

/// Local or VCS dependencies: deliberate, but not version-pinned.
const LOCAL_REQUIREMENTS: &[&str] = &["path", "git", "workspace", "file:"];

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(LockfilePresent),
        Box::new(UnpinnedDependencies),
        Box::new(DependencyInventory),
    ]
}

/// A lockfile next to a manifest that declares dependencies.
pub struct LockfilePresent;

impl Check for LockfilePresent {
    fn id(&self) -> &'static str {
        "lockfile-present"
    }

    fn definition_id(&self) -> &'static str {
        "dependencies"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut findings = Vec::new();
        let mut checked = 0usize;

        for analysis in context.analyses {
            if analysis.dependencies.is_empty() {
                continue;
            }
            checked += 1;
            let manifest = analysis
                .dependencies
                .manifests
                .first()
                .cloned()
                .unwrap_or_else(|| "(unknown manifest)".to_string());

            if analysis.dependencies.lockfile_present {
                let reference = evidence.insert(Evidence::file(
                    manifest.clone(),
                    format!(
                        "{}: {} declared dependencies with a lockfile",
                        analysis.language.label(),
                        analysis.dependencies.len()
                    ),
                ));
                findings.push(finding(
                    "dependencies",
                    spec,
                    Status::Pass,
                    &format!("{}/lockfile", analysis.language.id()),
                    format!(
                        "{} declares {} dependencies and a lockfile is present",
                        analysis.language.label(),
                        analysis.dependencies.len()
                    ),
                    vec![reference],
                ));
            } else {
                let reference = evidence.insert(Evidence::file(
                    manifest.clone(),
                    format!(
                        "{}: {} declared dependencies without a lockfile",
                        analysis.language.label(),
                        analysis.dependencies.len()
                    ),
                ));
                findings.push(finding(
                    "dependencies",
                    spec,
                    Status::Warn,
                    &format!("{}/lockfile", analysis.language.id()),
                    format!(
                        "{} declares {} dependencies but no lockfile is present, so a build is not reproducible",
                        analysis.language.label(),
                        analysis.dependencies.len()
                    ),
                    vec![reference],
                ));
            }
        }

        if checked == 0 {
            findings.push(pass(
                "dependencies",
                spec,
                "No manifest declares dependencies, so no lockfile is required",
                Vec::new(),
            ));
        }
        Ok(findings)
    }
}

/// Dependencies declared without a version constraint.
pub struct UnpinnedDependencies;

impl Check for UnpinnedDependencies {
    fn id(&self) -> &'static str {
        "unpinned-dependencies"
    }

    fn definition_id(&self) -> &'static str {
        "dependencies"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut unconstrained = 0usize;
        let mut local = 0usize;
        let mut findings = Vec::new();

        for dependency in context.dependencies() {
            let requirement = dependency
                .requirement
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let is_local = LOCAL_REQUIREMENTS
                .iter()
                .any(|prefix| requirement.starts_with(prefix));
            let is_unconstrained = UNPINNED_REQUIREMENTS.contains(&requirement.as_str());

            if is_local {
                local += 1;
                continue;
            }
            if !is_unconstrained {
                continue;
            }
            unconstrained += 1;
            let location = match dependency.line {
                Some(line) => format!("{}:{line}", dependency.manifest),
                None => dependency.manifest.clone(),
            };
            let reference = evidence.insert(Evidence::file(
                dependency.manifest.clone(),
                format!(
                    "{} is declared without a version constraint",
                    dependency.name
                ),
            ));
            findings.push(finding(
                "dependencies",
                spec,
                Status::Warn,
                &format!("{}:{}", dependency.manifest, dependency.name),
                format!(
                    "Dependency `{}` ({}) is declared in {location} without a version constraint",
                    dependency.name,
                    dependency.kind.id()
                ),
                vec![reference],
            ));
        }

        if findings.is_empty() {
            let mut description =
                "Every declared dependency carries a version constraint".to_string();
            if local > 0 {
                description.push_str(&format!(
                    "; {local} local or VCS dependenc(ies) are recorded separately and not treated as unpinned"
                ));
            }
            findings.push(pass("dependencies", spec, description, Vec::new()));
        }
        if unconstrained > 0 && local > 0 {
            findings.push(finding(
                "dependencies",
                spec,
                Status::Info,
                "local-dependencies",
                format!(
                    "{local} dependenc(ies) resolve from a local path or VCS rather than a registry"
                ),
                Vec::new(),
            ));
        }
        Ok(findings)
    }
}

/// A record of the declared dependency surface.
pub struct DependencyInventory;

impl Check for DependencyInventory {
    fn id(&self) -> &'static str {
        "dependency-inventory"
    }

    fn definition_id(&self) -> &'static str {
        "dependencies"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut findings = Vec::new();
        let mut total = 0usize;

        for analysis in context.analyses {
            if analysis.dependencies.is_empty() && analysis.dependencies.manifests.is_empty() {
                continue;
            }
            total += analysis.dependencies.len();
            let runtime = analysis
                .dependencies
                .by_kind(auditeur_languages::DependencyKind::Runtime)
                .len();
            let development = analysis
                .dependencies
                .by_kind(auditeur_languages::DependencyKind::Development)
                .len();
            let build = analysis
                .dependencies
                .by_kind(auditeur_languages::DependencyKind::Build)
                .len();

            let references: Vec<_> = analysis
                .dependencies
                .manifests
                .iter()
                .map(|manifest| {
                    evidence.insert(Evidence::file(
                        manifest.clone(),
                        format!("manifest parsed for {}", analysis.language.label()),
                    ))
                })
                .collect();

            let mut description = format!(
                "{} declares {} dependencies: {runtime} runtime, {development} development, {build} build",
                analysis.language.label(),
                analysis.dependencies.len()
            );
            if !analysis.dependencies.unparsed_manifests.is_empty() {
                description.push_str(&format!(
                    "; {} manifest(s) could not be parsed and are excluded from these counts",
                    analysis.dependencies.unparsed_manifests.len()
                ));
            }
            if !analysis.dependencies.notes.is_empty() {
                description.push_str(&format!("; {}", analysis.dependencies.notes.join("; ")));
            }

            findings.push(finding(
                "dependencies",
                spec,
                Status::Info,
                &format!("inventory/{}", analysis.language.id()),
                description,
                references,
            ));
        }

        if total == 0 && findings.is_empty() {
            findings.push(pass(
                "dependencies",
                spec,
                "No dependencies are declared in any detected manifest",
                Vec::new(),
            ));
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::run_check;
    use std::fs;

    fn rust_project(with_lockfile: bool) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nlocal = { path = \"../local\" }\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        if with_lockfile {
            fs::write(temp.path().join("Cargo.lock"), "version = 3\n").unwrap();
        }
        temp
    }

    #[test]
    fn a_declared_dependency_without_a_lockfile_is_a_warning() {
        let temp = rust_project(false);
        let (findings, _) = run_check("lockfile-present", "dependencies", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Warn);
        assert!(findings[0].description.contains("no lockfile"));
    }

    #[test]
    fn a_declared_dependency_with_a_lockfile_passes() {
        let temp = rust_project(true);
        let (findings, _) = run_check("lockfile-present", "dependencies", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn local_dependencies_are_separated_from_unpinned_ones() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"d\"\nversion = \"0.1.0\"\n\n[dependencies]\nfixed = \"1.2\"\nwobble = \"*\"\nlocal = { path = \"../x\" }\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();

        let (findings, _) = run_check("unpinned-dependencies", "dependencies", temp.path());
        let warn: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.status == Status::Warn)
            .collect();
        assert_eq!(warn.len(), 1, "{findings:?}");
        assert!(warn[0].description.contains("wobble"));
        assert!(findings
            .iter()
            .any(|finding| finding.check_id == "unpinned-dependencies"
                && finding.description.contains("local")));
    }

    #[test]
    fn fully_pinned_dependencies_pass() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"d\"\nversion = \"0.1.0\"\n\n[dependencies]\nfixed = \"1.2.3\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("unpinned-dependencies", "dependencies", temp.path());
        assert!(findings
            .iter()
            .any(|finding| finding.status == Status::Pass));
    }

    #[test]
    fn the_inventory_reports_counts_by_kind() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"d\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n\n[dev-dependencies]\ntempfile = \"3\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("dependency-inventory", "dependencies", temp.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("1 runtime"));
        assert!(findings[0].description.contains("1 development"));
        assert!(findings[0].has_evidence());
    }
}
