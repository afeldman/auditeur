//! Release-readiness checks: version declaration and repository state.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![Box::new(VersionDeclared), Box::new(GitWorkingTreeClean)]
}

/// A version declared in a manifest.
pub struct VersionDeclared;

impl Check for VersionDeclared {
    fn id(&self) -> &'static str {
        "version-declared"
    }

    fn definition_id(&self) -> &'static str {
        "release-readiness"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let declared: Vec<_> = context
            .analyses
            .iter()
            .filter_map(|analysis| {
                analysis
                    .version
                    .as_ref()
                    .map(|version| (analysis, version.clone()))
            })
            .collect();

        if declared.is_empty() {
            let deep = context
                .analyses
                .iter()
                .filter(|analysis| analysis.level == auditeur_languages::AnalysisLevel::Deep)
                .count();
            return Ok(vec![finding(
                "release-readiness",
                spec,
                Status::Warn,
                "version",
                format!(
                    "No manifest declares a version ({deep} manifest(s) were parsed in detail); a release cannot be pointed at a revision"
                ),
                Vec::new(),
            )]);
        }

        let references: Vec<_> = declared
            .iter()
            .map(|(analysis, version)| {
                let manifest = analysis
                    .dependencies
                    .manifests
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "(manifest)".to_string());
                evidence.insert(Evidence::config(
                    manifest,
                    "version",
                    format!("{} version {version}", analysis.language.label()),
                ))
            })
            .collect();

        let rendered: Vec<String> = declared
            .iter()
            .map(|(analysis, version)| format!("{} {version}", analysis.language.label()))
            .collect();

        Ok(vec![finding(
            "release-readiness",
            spec,
            Status::Info,
            "version",
            format!("Declared version(s): {}", rendered.join(", ")),
            references,
        )])
    }
}

/// Whether the working tree matches the recorded revision.
pub struct GitWorkingTreeClean;

impl Check for GitWorkingTreeClean {
    fn id(&self) -> &'static str {
        "git-working-tree-clean"
    }

    fn definition_id(&self) -> &'static str {
        "release-readiness"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let Some(git) = context.git else {
            return Ok(vec![finding(
                "release-readiness",
                spec,
                Status::Info,
                "git",
                "The audited path is not a Git work tree, so no revision can be recorded and the audit describes the filesystem as it was",
                Vec::new(),
            )]);
        };

        let revision = git
            .head_commit
            .as_deref()
            .map(|commit| commit.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "(no commit)".to_string());
        let branch = git.branch.as_deref().unwrap_or("(detached)");

        let reference = evidence.insert(Evidence::new(
            auditeur_model::EvidenceKind::GitRef,
            auditeur_model::EvidenceLocation::Git {
                commit: git.head_commit.clone().unwrap_or_default(),
                reference: git.branch.clone(),
            },
            format!("audited revision {revision} on {branch}"),
        ));

        if git.is_clean() {
            return Ok(vec![finding(
                "release-readiness",
                spec,
                Status::Pass,
                "git-state",
                format!("Working tree matches {revision} on {branch}; no uncommitted changes"),
                vec![reference],
            )]);
        }

        Ok(vec![finding(
            "release-readiness",
            spec,
            Status::Info,
            "git-state",
            format!(
                "Working tree differs from {revision}: {} modified and {} untracked file(s); this audit describes the tree on disk, not the commit",
                git.modified_files, git.untracked_files
            ),
            vec![reference],
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{run_check, Fixture};
    use auditeur_model::GitState;
    use std::fs;

    #[test]
    fn a_declared_version_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"2.3.4\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("version-declared", "release-readiness", temp.path());
        assert_eq!(findings[0].status, Status::Info);
        assert!(findings[0].description.contains("2.3.4"));
    }

    #[test]
    fn a_missing_version_warns() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion.workspace = true\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("version-declared", "release-readiness", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }

    #[test]
    fn without_git_the_check_is_informational_not_a_failure() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let (findings, _) = run_check("git-working-tree-clean", "release-readiness", temp.path());
        assert_eq!(findings[0].status, Status::Info);
        assert!(findings[0].description.contains("not a Git work tree"));
    }

    #[test]
    fn a_dirty_tree_is_reported_as_describing_the_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let fixture = Fixture::new(temp.path());
        let git = GitState {
            head_commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            branch: Some("feature/x".to_string()),
            describe: None,
            remote: None,
            dirty: true,
            modified_files: 2,
            untracked_files: 1,
        };
        let check = crate::checks::find("git-working-tree-clean").unwrap();
        let mut store = EvidenceStore::new();
        let context = crate::context::AuditContext::new(
            &fixture.model,
            &fixture.analyses,
            &fixture.config,
            Some(&git),
        );
        let findings = check
            .run(
                &context,
                &mut store,
                &crate::testsupport::spec("release-readiness", "git-working-tree-clean"),
            )
            .unwrap();
        assert_eq!(findings[0].status, Status::Info);
        assert!(findings[0].description.contains("2 modified"));
        assert!(findings[0].description.contains("1 untracked"));
        assert_eq!(findings[0].evidence.len(), 1);
    }

    #[test]
    fn a_clean_tree_passes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let fixture = Fixture::new(temp.path());
        let git = GitState {
            head_commit: Some("abcdef0123456789abcdef0123456789abcdef01".to_string()),
            branch: Some("main".to_string()),
            describe: None,
            remote: None,
            dirty: false,
            modified_files: 0,
            untracked_files: 0,
        };
        let check = crate::checks::find("git-working-tree-clean").unwrap();
        let mut store = EvidenceStore::new();
        let context = crate::context::AuditContext::new(
            &fixture.model,
            &fixture.analyses,
            &fixture.config,
            Some(&git),
        );
        let findings = check
            .run(
                &context,
                &mut store,
                &crate::testsupport::spec("release-readiness", "git-working-tree-clean"),
            )
            .unwrap();
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn an_empty_repository_is_not_a_release_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let (findings, _) = run_check("version-declared", "release-readiness", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }
}
