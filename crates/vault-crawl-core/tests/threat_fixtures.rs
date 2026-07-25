use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;
use vault_crawl_core::contract::{ProjectId, SourceSurface};
use vault_crawl_core::policy::{NetworkProfile, normalize_url, resolve_destination};
use vault_crawl_core::threat::{
    CapabilityCeiling, Decision, RequestedAuthority, evaluate_authority, evaluate_managed_path,
    evaluate_pinned_resolution, evaluate_proxy_environment,
};

#[derive(Debug, Deserialize)]
struct FixtureFile {
    version: String,
    cases: Vec<ThreatCase>,
}

#[derive(Debug, Deserialize)]
struct TransitionFixtureFile {
    schema_version: String,
    implementation_status: String,
    cases: Vec<TransitionThreatCase>,
}

#[derive(Debug, Deserialize)]
struct TransitionThreatCase {
    name: String,
    boundary: String,
    example: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ThreatCase {
    AddressPinning {
        name: String,
        resolved: Vec<IpAddr>,
        selected: IpAddr,
        connected_peer: IpAddr,
        expected: String,
    },
    Proxy {
        name: String,
        environment_keys: Vec<String>,
        expected: String,
    },
    Path {
        name: String,
        root: String,
        candidate: String,
        expected: String,
    },
    Authority {
        name: String,
        bound_caller: String,
        bound_surface: SourceSurface,
        allowed_projects: BTreeSet<ProjectId>,
        allowed_capabilities: BTreeSet<String>,
        requested_caller: String,
        requested_surface: SourceSurface,
        requested_project: ProjectId,
        requested_capabilities: BTreeSet<String>,
        expected: String,
    },
}

fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allowed => "allowed",
        Decision::Refused(_) => "refused",
    }
}

#[test]
fn phase_zero_threat_matrix_runs_offline() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/threat/cases.v1.json");
    let fixture: FixtureFile = serde_json::from_slice(&fs::read(&path).expect("read threat cases"))
        .expect("parse threat cases");
    assert_eq!(fixture.version, "1.0.0");
    assert!(fixture.cases.len() >= 21, "threat corpus is too small");

    for case in fixture.cases {
        let (name, expected, decision) = match case {
            ThreatCase::AddressPinning {
                name,
                resolved,
                selected,
                connected_peer,
                expected,
            } => {
                let decision = evaluate_pinned_resolution(&resolved, selected, connected_peer);
                (name, expected, decision)
            }
            ThreatCase::Proxy {
                name,
                environment_keys,
                expected,
            } => {
                let decision =
                    evaluate_proxy_environment(environment_keys.iter().map(String::as_str));
                (name, expected, decision)
            }
            ThreatCase::Path {
                name,
                root,
                candidate,
                expected,
            } => {
                let decision = evaluate_managed_path(Path::new(&root), Path::new(&candidate));
                (name, expected, decision)
            }
            ThreatCase::Authority {
                name,
                bound_caller,
                bound_surface,
                allowed_projects,
                allowed_capabilities,
                requested_caller,
                requested_surface,
                requested_project,
                requested_capabilities,
                expected,
            } => {
                let ceiling = CapabilityCeiling {
                    caller: bound_caller,
                    source_surface: bound_surface,
                    allowed_projects,
                    capabilities: allowed_capabilities,
                };
                let request = RequestedAuthority {
                    caller: requested_caller,
                    source_surface: requested_surface,
                    project: requested_project,
                    capabilities: requested_capabilities,
                };
                let decision = evaluate_authority(&ceiling, &request);
                (name, expected, decision)
            }
        };
        assert_eq!(
            decision_name(&decision),
            expected,
            "fixture {name}: {decision:?}"
        );
    }
}

#[test]
fn phase_one_transition_cases_are_bound_to_runtime_policy() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/threat/deferred-phase1-cases.v1.json");
    let fixture: TransitionFixtureFile =
        serde_json::from_slice(&fs::read(&path).expect("read transition threat cases"))
            .expect("parse transition threat cases");
    assert_eq!(fixture.schema_version, "1.0.0");
    assert_eq!(fixture.implementation_status, "implemented-phase1");
    assert!(fixture.cases.len() >= 13);

    let names = fixture
        .cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "integer-ipv4-form",
        "shortened-ipv4-form",
        "ipv6-zone-identifier",
        "userinfo-host-confusion",
        "public-nonstandard-port-without-allowlist",
        "platform-pac-proxy",
        "public-to-private-redirect",
        "redirect-dns-answer-change",
        "validation-to-connect-dns-rebinding",
    ] {
        assert!(
            names.contains(required),
            "missing transition case {required}"
        );
    }
    assert!(
        fixture
            .cases
            .iter()
            .all(|case| { !case.boundary.trim().is_empty() && !case.example.trim().is_empty() })
    );

    for input in ["http://2130706433/", "http://127.1/"] {
        let normalized = normalize_url(input).expect("URL parser normalizes numeric host");
        assert!(
            resolve_destination(&normalized.normalized, NetworkProfile::AutomaticPublic).is_err(),
            "numeric loopback form must fail before connect: {input}"
        );
    }
    assert!(normalize_url("http://[fe80::1%25en0]/").is_err());
    assert!(normalize_url("http://public.example@[::1]/").is_err());
    assert!(normalize_url("file:///etc/passwd").is_err());
    assert!(normalize_url("https://example.invalid:8443/").is_err());
}
