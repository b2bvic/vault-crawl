//! Phase 0 adapter contracts.
//!
//! No source-native or search-provider adapter is implemented in Phase 0.

use serde::{Deserialize, Serialize};
use vault_crawl_core::contract::ProjectId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRecord {
    pub schema_version: String,
    pub record_id: String,
    pub project: ProjectId,
    pub execution_host: String,
    pub adapter: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryDecision {
    AcceptedInactive,
    RefusedPhaseZeroActivation,
}

/// Imported registry records can be represented in Phase 0 but cannot be
/// activated. This keeps the skeleton incapable of collection.
#[must_use]
pub const fn validate_phase_zero_registry(record: &RegistryRecord) -> RegistryDecision {
    if record.active {
        RegistryDecision::RefusedPhaseZeroActivation
    } else {
        RegistryDecision::AcceptedInactive
    }
}

#[cfg(test)]
mod tests {
    use super::{RegistryDecision, RegistryRecord, validate_phase_zero_registry};
    use vault_crawl_core::contract::ProjectId;

    #[test]
    fn phase_zero_refuses_active_registry_record() {
        let record = RegistryRecord {
            schema_version: "1.0.0".to_owned(),
            record_id: "fixture".to_owned(),
            project: ProjectId::new("example").expect("project ID"),
            execution_host: "fixture-host".to_owned(),
            adapter: "not-built".to_owned(),
            active: true,
        };
        assert_eq!(
            validate_phase_zero_registry(&record),
            RegistryDecision::RefusedPhaseZeroActivation
        );
    }
}
