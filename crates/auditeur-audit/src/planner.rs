//! Audit planning.
//!
//! The planner decides what an audit will actually do, and records what it
//! will not do. Scope is therefore a computed, inspectable artifact rather than
//! something a reader has to infer from the report: the plan is part of the run
//! and its quantities appear in the manifest.

use auditeur_config::AuditConfig;
use auditeur_model::{AuditCategory, DefinitionRef};

use crate::definitions::{AuditDefinition, CheckKind, CheckSpec};
use crate::error::AuditError;

/// A deterministic check the plan selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCheck {
    /// Definition the check belongs to.
    pub definition_id: String,
    /// The declared check.
    pub spec: CheckSpec,
}

/// A model-assisted task the plan selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTask {
    /// Definition the check belongs to.
    pub definition_id: String,
    /// The declared check, which carries the task objective.
    pub spec: CheckSpec,
}

/// A check the plan declined to run, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSkip {
    /// Definition id.
    pub definition_id: String,
    /// Check id.
    pub check_id: String,
    /// Why it was skipped.
    pub reason: String,
}

/// What an audit will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPlan {
    /// Definitions that contributed at least one check.
    pub definitions: Vec<DefinitionRef>,
    /// Deterministic checks to run.
    pub checks: Vec<PlannedCheck>,
    /// Model-assisted tasks to run.
    pub tasks: Vec<PlannedTask>,
    /// Checks that were not selected, and why.
    pub skipped: Vec<PlanSkip>,
    /// Categories enabled for this run.
    pub categories: Vec<AuditCategory>,
    /// Whether model-assisted analysis is part of this plan.
    pub ai_enabled: bool,
}

impl AuditPlan {
    /// Build a plan from the loaded definitions and configuration.
    ///
    /// A declared deterministic check without an implementation is an error, not
    /// a skip: silently ignoring it would mean a definition claims coverage the
    /// binary cannot deliver.
    pub fn build(
        definitions: &[AuditDefinition],
        config: &AuditConfig,
        ai_enabled: bool,
    ) -> Result<Self, AuditError> {
        let mut plan = AuditPlan {
            definitions: Vec::new(),
            checks: Vec::new(),
            tasks: Vec::new(),
            skipped: Vec::new(),
            categories: config.enabled_categories.clone(),
            ai_enabled,
        };

        for definition in definitions {
            let mut contributed = false;

            for spec in &definition.checks {
                if !config.is_enabled(spec.category) {
                    plan.skipped.push(PlanSkip {
                        definition_id: definition.id.clone(),
                        check_id: spec.id.clone(),
                        reason: format!("category '{}' is disabled", spec.category.id()),
                    });
                    continue;
                }

                match spec.kind {
                    CheckKind::Deterministic | CheckKind::Hybrid => {
                        if crate::checks::find(&spec.id).is_none() {
                            return Err(AuditError::MissingImplementation {
                                definition: definition.id.clone(),
                                check: spec.id.clone(),
                            });
                        }
                        plan.checks.push(PlannedCheck {
                            definition_id: definition.id.clone(),
                            spec: spec.clone(),
                        });
                        contributed = true;
                    }
                    CheckKind::AiAssisted => {}
                }

                if spec.kind.needs_model() {
                    if ai_enabled {
                        plan.tasks.push(PlannedTask {
                            definition_id: definition.id.clone(),
                            spec: spec.clone(),
                        });
                        contributed = true;
                    } else {
                        plan.skipped.push(PlanSkip {
                            definition_id: definition.id.clone(),
                            check_id: spec.id.clone(),
                            reason: "model-assisted analysis is disabled for this run".to_string(),
                        });
                    }
                }
            }

            if contributed {
                plan.definitions.push(definition.reference());
            }
        }

        plan.checks
            .sort_by(|left, right| left.spec.id.cmp(&right.spec.id));
        plan.tasks
            .sort_by(|left, right| left.spec.id.cmp(&right.spec.id));
        plan.definitions
            .sort_by(|left, right| left.id.cmp(&right.id));
        Ok(plan)
    }

    /// Number of deterministic checks selected.
    pub fn checks_selected(&self) -> u32 {
        self.checks.len() as u32
    }

    /// Number of model-assisted tasks selected.
    pub fn tasks_selected(&self) -> u32 {
        self.tasks.len() as u32
    }

    /// Findings the plan did not run, as one-line descriptions.
    pub fn skip_descriptions(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(|skip| format!("{}/{}: {}", skip.definition_id, skip.check_id, skip.reason))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definitions() -> Vec<AuditDefinition> {
        crate::definitions::embedded().unwrap()
    }

    #[test]
    fn the_default_configuration_plans_every_deterministic_check() {
        let config = AuditConfig::default();
        let plan = AuditPlan::build(&definitions(), &config, false).unwrap();
        assert_eq!(
            plan.checks_selected() as usize,
            crate::checks::implementations().len()
        );
        assert!(plan.tasks.is_empty());
        // The model-assisted checks are recorded as skipped, not forgotten.
        assert!(!plan.skipped.is_empty());
        assert!(plan
            .skipped
            .iter()
            .all(|skip| skip.reason.contains("model-assisted")));
    }

    #[test]
    fn enabling_ai_plans_the_tasks_too() {
        let config = AuditConfig::default();
        let plan = AuditPlan::build(&definitions(), &config, true).unwrap();
        assert!(plan.tasks_selected() >= 3);
        assert!(plan.ai_enabled);
        assert!(plan
            .skipped
            .iter()
            .all(|skip| !skip.reason.contains("model-assisted")));
    }

    #[test]
    fn a_disabled_category_removes_its_checks() {
        let config = AuditConfig {
            enabled_categories: vec![AuditCategory::Security],
            ..AuditConfig::default()
        };
        let plan = AuditPlan::build(&definitions(), &config, false).unwrap();
        assert!(plan
            .checks
            .iter()
            .all(|check| check.spec.category == AuditCategory::Security));
        assert!(plan
            .skipped
            .iter()
            .any(|skip| skip.reason.contains("category 'testing' is disabled")));
        assert_eq!(plan.definitions.len(), 1);
        assert_eq!(plan.definitions[0].id, "security");
    }

    #[test]
    fn a_declared_check_without_an_implementation_is_an_error() {
        let definition = AuditDefinition {
            id: "ghost".to_string(),
            version: "1.0.0".to_string(),
            title: "Ghost".to_string(),
            description: String::new(),
            checks: vec![CheckSpec {
                id: "no-such-check".to_string(),
                title: "Missing".to_string(),
                description: String::new(),
                kind: CheckKind::Deterministic,
                category: AuditCategory::Security,
                severity: auditeur_model::Severity::Low,
                recommendation: None,
                objective: None,
            }],
        };
        let error = AuditPlan::build(&[definition], &AuditConfig::default(), false).unwrap_err();
        assert!(
            matches!(error, AuditError::MissingImplementation { .. }),
            "{error}"
        );
    }

    #[test]
    fn planning_is_deterministic() {
        let config = AuditConfig::default();
        let first = AuditPlan::build(&definitions(), &config, true).unwrap();
        let second = AuditPlan::build(&definitions(), &config, true).unwrap();
        assert_eq!(first, second);
        let check_ids: Vec<&str> = first
            .checks
            .iter()
            .map(|check| check.spec.id.as_str())
            .collect();
        let mut sorted = check_ids.clone();
        sorted.sort_unstable();
        assert_eq!(check_ids, sorted, "check order must be canonical");
    }

    #[test]
    fn skip_descriptions_name_the_check_and_the_reason() {
        let config = AuditConfig {
            enabled_categories: vec![AuditCategory::Security],
            ..AuditConfig::default()
        };
        let plan = AuditPlan::build(&definitions(), &config, false).unwrap();
        let descriptions = plan.skip_descriptions();
        assert!(!descriptions.is_empty());
        assert!(descriptions
            .iter()
            .all(|description| description.contains('/')));
    }
}
