use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A caller-configured project boundary.
///
/// The core has no built-in project list. Operators select any set of
/// lower-case identifiers that pass this validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    /// Validate and construct a project identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty identifier or characters outside
    /// lower-case ASCII letters, digits, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(
                "project ID must be 1-64 lower-case letters, digits, `_`, or `-`".to_owned(),
            );
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProjectId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Backward-compatible type name for persisted `lane` fields. Values are
/// dynamic project IDs, not a fixed enum.
pub type Lane = ProjectId;

/// The generic surface that introduced a request. This is server-bound state,
/// not a label supplied by downloaded content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceSurface {
    Cli,
    ScheduledWrapper,
    McpReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Status,
    Doctor,
    StaticFetch,
    CorpusQuery,
    ManualRender,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationState {
    Available,
    NotBuilt,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapability {
    pub capability: Capability,
    pub state: ImplementationState,
    pub automatic: bool,
}

#[must_use]
pub fn phase_zero_capabilities() -> Vec<RuntimeCapability> {
    [
        (Capability::Status, ImplementationState::Available),
        (Capability::Doctor, ImplementationState::Available),
        (Capability::StaticFetch, ImplementationState::NotBuilt),
        (Capability::CorpusQuery, ImplementationState::NotBuilt),
        (Capability::ManualRender, ImplementationState::NotBuilt),
    ]
    .into_iter()
    .map(|(capability, state)| RuntimeCapability {
        capability,
        state,
        automatic: false,
    })
    .collect()
}

#[must_use]
pub fn phase_one_capabilities() -> Vec<RuntimeCapability> {
    [
        (Capability::Status, ImplementationState::Available),
        (Capability::Doctor, ImplementationState::Available),
        (Capability::StaticFetch, ImplementationState::Available),
        (Capability::CorpusQuery, ImplementationState::Available),
        (Capability::ManualRender, ImplementationState::NotBuilt),
    ]
    .into_iter()
    .map(|(capability, state)| RuntimeCapability {
        capability,
        state,
        automatic: false,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{Capability, ImplementationState, ProjectId, phase_one_capabilities};

    #[test]
    fn project_ids_are_user_defined_and_validated() {
        assert_eq!(
            ProjectId::new("research-ops")
                .expect("valid project")
                .as_str(),
            "research-ops"
        );
        assert!(ProjectId::new("../escape").is_err());
        assert!(ProjectId::new("Uppercase").is_err());
    }

    #[test]
    fn phase_one_exposes_static_read_only_capabilities_only() {
        let capabilities = phase_one_capabilities();
        assert!(capabilities.iter().all(|capability| !capability.automatic));
        assert!(capabilities.iter().any(|capability| {
            capability.capability == Capability::StaticFetch
                && capability.state == ImplementationState::Available
        }));
        assert!(capabilities.iter().all(|capability| {
            capability.capability != Capability::ManualRender
                || capability.state == ImplementationState::NotBuilt
        }));
    }
}
