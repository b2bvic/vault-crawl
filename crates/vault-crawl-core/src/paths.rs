use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::contract::ProjectId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectRoots {
    pub project: ProjectId,
    pub database: PathBuf,
    pub blobs: PathBuf,
    pub logs: PathBuf,
    pub compact_receipts: PathBuf,
}

/// Compute isolated roots for an arbitrary caller-supplied project set.
#[must_use]
pub fn project_roots(
    state_base: &Path,
    receipt_base: &Path,
    projects: &[ProjectId],
) -> Vec<ProjectRoots> {
    projects
        .iter()
        .map(|project| {
            let state = state_base.join(project.as_str());
            ProjectRoots {
                project: project.clone(),
                database: state.join("state.sqlite3"),
                blobs: state.join("blobs"),
                logs: state.join("logs"),
                compact_receipts: receipt_base.join(project.as_str()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::project_roots;
    use crate::contract::ProjectId;

    #[test]
    fn arbitrary_project_sets_receive_separate_roots() {
        let projects = ["research", "operations", "personal"]
            .into_iter()
            .map(|value| ProjectId::new(value).expect("project ID"))
            .collect::<Vec<_>>();
        let roots = project_roots(
            Path::new("/workspace/state"),
            Path::new("/workspace/receipts"),
            &projects,
        );
        assert_eq!(roots.len(), projects.len());
        assert_eq!(
            roots
                .iter()
                .map(|root| &root.database)
                .collect::<BTreeSet<_>>()
                .len(),
            projects.len()
        );
        assert_eq!(
            roots
                .iter()
                .map(|root| &root.compact_receipts)
                .collect::<BTreeSet<_>>()
                .len(),
            projects.len()
        );
    }
}
