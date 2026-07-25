use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::contract::{ProjectId, SourceSurface};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    EmptyResolution,
    ForbiddenAddress,
    MixedAddressSet,
    SelectedAddressNotResolved,
    ConnectedPeerMismatch,
    AmbientProxy,
    PathEscape,
    ProjectEscalation,
    CapabilityEscalation,
    SourceSurfaceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Refused(RefusalReason),
}

/// Pure Phase 0 address-pinning contract. No socket is opened.
#[must_use]
pub fn evaluate_pinned_resolution(
    resolved: &[IpAddr],
    selected: IpAddr,
    connected_peer: IpAddr,
) -> Decision {
    if resolved.is_empty() {
        return Decision::Refused(RefusalReason::EmptyResolution);
    }

    let has_forbidden = resolved.iter().any(|address| !is_public_address(*address));
    let has_public = resolved.iter().any(|address| is_public_address(*address));
    if has_forbidden && has_public {
        return Decision::Refused(RefusalReason::MixedAddressSet);
    }
    if has_forbidden {
        return Decision::Refused(RefusalReason::ForbiddenAddress);
    }
    if !resolved.contains(&selected) {
        return Decision::Refused(RefusalReason::SelectedAddressNotResolved);
    }
    if connected_peer != selected {
        return Decision::Refused(RefusalReason::ConnectedPeerMismatch);
    }
    Decision::Allowed
}

#[must_use]
pub fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    if address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_unspecified()
    {
        return false;
    }

    !matches!(
        (a, b, c, d),
        (0 | 240..=255, _, _, _)
            | (100, 64..=127, _, _)
            | (192, 0, 0 | 2, _)
            | (192, 88, 99, _)
            | (198, 18..=19, _, _)
            | (198, 51, 100, _)
            | (203, 0, 113, _)
    )
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = address.segments();
    if address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
    {
        return false;
    }
    // Documentation prefix 2001:db8::/32 and discard-only 100::/64.
    !((segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]))
}

/// Phase 0 has no proxy adapter. Any ambient proxy variable produces a typed
/// refusal instead of changing routing.
#[must_use]
pub fn evaluate_proxy_environment<'a>(keys: impl IntoIterator<Item = &'a str>) -> Decision {
    const PROXY_KEYS: &[&str] = &["http_proxy", "https_proxy", "all_proxy", "no_proxy"];
    if keys
        .into_iter()
        .any(|key| PROXY_KEYS.contains(&key.to_ascii_lowercase().as_str()))
    {
        Decision::Refused(RefusalReason::AmbientProxy)
    } else {
        Decision::Allowed
    }
}

/// Lexically validates a managed destination before filesystem access. Phase 0
/// does not accept a symlink-containing destination; callers must separately
/// canonicalize an existing root before this check.
#[must_use]
pub fn evaluate_managed_path(root: &Path, candidate: &Path) -> Decision {
    let Some(root) = lexical_absolute(root) else {
        return Decision::Refused(RefusalReason::PathEscape);
    };
    let Some(candidate) = lexical_absolute(candidate) else {
        return Decision::Refused(RefusalReason::PathEscape);
    };
    if candidate.starts_with(root) {
        Decision::Allowed
    } else {
        Decision::Refused(RefusalReason::PathEscape)
    }
}

/// Canonicalizes an existing root and candidate to detect symlink escape.
/// Unreadable or missing paths fail closed.
#[must_use]
pub fn evaluate_canonical_managed_path(root: &Path, candidate: &Path) -> Decision {
    let Ok(root) = std::fs::canonicalize(root) else {
        return Decision::Refused(RefusalReason::PathEscape);
    };
    let Ok(candidate) = std::fs::canonicalize(candidate) else {
        return Decision::Refused(RefusalReason::PathEscape);
    };
    if candidate.starts_with(root) {
        Decision::Allowed
    } else {
        Decision::Refused(RefusalReason::PathEscape)
    }
}

fn lexical_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                clean.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => return None,
        }
    }
    Some(clean)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCeiling {
    pub caller: String,
    pub source_surface: SourceSurface,
    pub allowed_projects: BTreeSet<ProjectId>,
    pub capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAuthority {
    pub caller: String,
    pub source_surface: SourceSurface,
    pub project: ProjectId,
    pub capabilities: BTreeSet<String>,
}

/// Request fields may narrow, but cannot raise, the server-selected ceiling.
#[must_use]
pub fn evaluate_authority(ceiling: &CapabilityCeiling, request: &RequestedAuthority) -> Decision {
    if request.caller != ceiling.caller || request.source_surface != ceiling.source_surface {
        return Decision::Refused(RefusalReason::SourceSurfaceMismatch);
    }
    if !ceiling.allowed_projects.contains(&request.project) {
        return Decision::Refused(RefusalReason::ProjectEscalation);
    }
    if !request.capabilities.is_subset(&ceiling.capabilities) {
        return Decision::Refused(RefusalReason::CapabilityEscalation);
    }
    Decision::Allowed
}

#[must_use]
pub fn phase_zero_capability_names() -> BTreeSet<String> {
    ["status", "doctor"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    use super::{
        CapabilityCeiling, Decision, RefusalReason, RequestedAuthority, evaluate_authority,
        evaluate_canonical_managed_path, evaluate_managed_path, evaluate_pinned_resolution,
        evaluate_proxy_environment, is_public_address, phase_zero_capability_names,
    };
    use crate::contract::{ProjectId, SourceSurface};

    #[test]
    fn mixed_and_rebound_address_sets_fail_closed() {
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            evaluate_pinned_resolution(&[public, private], public, public),
            Decision::Refused(RefusalReason::MixedAddressSet)
        );
        assert_eq!(
            evaluate_pinned_resolution(&[public], public, private),
            Decision::Refused(RefusalReason::ConnectedPeerMismatch)
        );
    }

    #[test]
    fn deprecated_site_local_ipv6_is_not_public() {
        let site_local = IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1));
        assert!(!is_public_address(site_local));
        assert_eq!(
            evaluate_pinned_resolution(&[site_local], site_local, site_local),
            Decision::Refused(RefusalReason::ForbiddenAddress)
        );
    }

    #[test]
    fn ambient_proxy_fails_closed() {
        assert_eq!(
            evaluate_proxy_environment(["PATH", "HTTPS_PROXY"]),
            Decision::Refused(RefusalReason::AmbientProxy)
        );
    }

    #[test]
    fn managed_paths_refuse_traversal() {
        assert_eq!(
            evaluate_managed_path(
                Path::new("/tmp/vault-crawl/project-a"),
                Path::new("/tmp/vault-crawl/project-a/../project-b/receipt.json")
            ),
            Decision::Refused(RefusalReason::PathEscape)
        );
        assert_eq!(
            evaluate_managed_path(
                Path::new("/tmp/vault-crawl/project-a"),
                Path::new("/tmp/vault-crawl/project-a/receipts/run.json")
            ),
            Decision::Allowed
        );
    }

    #[test]
    fn request_cannot_raise_server_bound_authority() {
        let ceiling = CapabilityCeiling {
            caller: "project-a-cli".to_owned(),
            source_surface: SourceSurface::Cli,
            allowed_projects: BTreeSet::from([ProjectId::new("project-a").expect("project ID")]),
            capabilities: phase_zero_capability_names(),
        };
        let elevated = RequestedAuthority {
            caller: "project-a-cli".to_owned(),
            source_surface: SourceSurface::Cli,
            project: ProjectId::new("project-b").expect("project ID"),
            capabilities: BTreeSet::from(["status".to_owned()]),
        };
        assert_eq!(
            evaluate_authority(&ceiling, &elevated),
            Decision::Refused(RefusalReason::ProjectEscalation)
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_path_check_refuses_symlink_escape() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("vault-crawl-threat-{}-{nonce}", std::process::id()));
        let managed = base.join("managed");
        let outside = base.join("outside");
        fs::create_dir_all(&managed).expect("create managed test directory");
        fs::create_dir_all(&outside).expect("create outside test directory");
        fs::write(outside.join("evidence"), b"fixture").expect("write outside fixture");
        symlink(&outside, managed.join("escape")).expect("create test symlink");

        assert_eq!(
            evaluate_canonical_managed_path(&managed, &managed.join("escape/evidence")),
            Decision::Refused(RefusalReason::PathEscape)
        );
        fs::remove_dir_all(&base).expect("remove test fixture tree");
    }
}
