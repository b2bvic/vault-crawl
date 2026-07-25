#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::{CrawlError, Result};
use crate::threat::is_public_address;

pub const NORMALIZATION_POLICY_VERSION: &str = "1.0.0";
pub const DEFAULT_ALLOWED_PORTS: &[u16] = &[80, 443];

const TRACKING_PARAMETERS: &[&str] = &[
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "ref_src",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedUrl {
    pub original: String,
    pub normalized: Url,
    pub normalization_policy_version: String,
    pub removed_tracking_parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedDestination {
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub selected: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProfile {
    AutomaticPublic,
    FixtureLoopback,
}

pub fn normalize_url(input: &str) -> Result<NormalizedUrl> {
    normalize_url_for_profile(input, NetworkProfile::AutomaticPublic)
}

pub fn normalize_url_for_profile(input: &str, profile: NetworkProfile) -> Result<NormalizedUrl> {
    let mut url = Url::parse(input.trim())
        .map_err(|error| CrawlError::InvalidInput(format!("invalid URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CrawlError::Refused(format!(
            "unsupported scheme {}",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CrawlError::Refused(
            "URLs containing user-info credentials are not allowed".to_owned(),
        ));
    }
    let Some(host) = url.host() else {
        return Err(CrawlError::InvalidInput("URL has no host".to_owned()));
    };
    if matches!(host, Host::Domain(domain) if domain.ends_with('.')) {
        let trimmed = url
            .host_str()
            .ok_or_else(|| CrawlError::InvalidInput("URL has no host".to_owned()))?
            .trim_end_matches('.')
            .to_owned();
        url.set_host(Some(&trimmed))
            .map_err(|_| CrawlError::InvalidInput("invalid trailing-dot host".to_owned()))?;
    }
    url.set_fragment(None);

    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for (key, value) in url.query_pairs() {
        if TRACKING_PARAMETERS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
        {
            removed.push(key.into_owned());
        } else {
            kept.push((key.into_owned(), value.into_owned()));
        }
    }
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(&kept);
    }
    removed.sort();
    removed.dedup();

    let port = url.port_or_known_default().ok_or_else(|| {
        CrawlError::Refused(format!(
            "scheme {} has no allowed default port",
            url.scheme()
        ))
    })?;
    if !DEFAULT_ALLOWED_PORTS.contains(&port) && !matches!(profile, NetworkProfile::FixtureLoopback)
    {
        return Err(CrawlError::Refused(format!(
            "port {port} is not allowlisted for automatic retrieval"
        )));
    }

    Ok(NormalizedUrl {
        original: input.to_owned(),
        normalized: url,
        normalization_policy_version: NORMALIZATION_POLICY_VERSION.to_owned(),
        removed_tracking_parameters: removed,
    })
}

pub fn refuse_ambient_proxies() -> Result<()> {
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        if std::env::var_os(key).is_some() {
            return Err(CrawlError::Refused(format!(
                "ambient proxy variable {key} is set"
            )));
        }
    }
    Ok(())
}

pub fn resolve_destination(url: &Url, profile: NetworkProfile) -> Result<ApprovedDestination> {
    let host = url
        .host_str()
        .ok_or_else(|| CrawlError::InvalidInput("URL has no host".to_owned()))?
        .to_owned();
    if host.contains('%') {
        return Err(CrawlError::Refused(
            "IPv6 zone identifiers are not allowed".to_owned(),
        ));
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        CrawlError::Refused(format!(
            "scheme {} has no allowed default port",
            url.scheme()
        ))
    })?;
    let addresses = match url.host() {
        Some(Host::Ipv4(address)) => vec![IpAddr::V4(address)],
        Some(Host::Ipv6(address)) => vec![IpAddr::V6(address)],
        Some(Host::Domain(_)) => (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| CrawlError::Network(format!("DNS resolution failed: {error}")))?
            .map(|address| address.ip())
            .collect(),
        None => Vec::new(),
    };
    approve_resolved_destination(url, profile, addresses)
}

pub fn approve_resolved_destination(
    url: &Url,
    profile: NetworkProfile,
    mut addresses: Vec<IpAddr>,
) -> Result<ApprovedDestination> {
    let host = url
        .host_str()
        .ok_or_else(|| CrawlError::InvalidInput("URL has no host".to_owned()))?
        .to_owned();
    let port = url.port_or_known_default().ok_or_else(|| {
        CrawlError::Refused(format!(
            "scheme {} has no allowed default port",
            url.scheme()
        ))
    })?;
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(CrawlError::Refused(
            "DNS resolution returned no addresses".to_owned(),
        ));
    }

    let allowed = |address: IpAddr| match profile {
        NetworkProfile::AutomaticPublic => is_public_address(address),
        NetworkProfile::FixtureLoopback => address.is_loopback(),
    };
    let allowed_count = addresses
        .iter()
        .copied()
        .filter(|address| allowed(*address))
        .count();
    if allowed_count != addresses.len() {
        let has_allowed = allowed_count > 0;
        let reason = if has_allowed {
            "mixed allowed and forbidden DNS answer set"
        } else {
            "destination resolves only to forbidden addresses"
        };
        return Err(CrawlError::Refused(reason.to_owned()));
    }

    let selected = addresses[0];
    Ok(ApprovedDestination {
        host,
        port,
        addresses,
        selected,
    })
}

#[must_use]
pub fn connected_peer_is_approved(peer: SocketAddr, approved: &ApprovedDestination) -> bool {
    peer.port() == approved.port && approved.addresses.contains(&peer.ip())
}

#[must_use]
pub fn origin(url: &Url) -> String {
    let port = url.port_or_known_default().unwrap_or_default();
    format!(
        "{}://{}:{port}",
        url.scheme(),
        url.host_str().unwrap_or_default()
    )
}

#[must_use]
pub fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[must_use]
pub fn redacted_url(url: &Url) -> String {
    let sensitive: BTreeSet<String> = [
        ["access", "token"].join("_"),
        ["api", "key"].join("_"),
        "apikey".to_owned(),
        "auth".to_owned(),
        "key".to_owned(),
        "password".to_owned(),
        "signature".to_owned(),
        "sig".to_owned(),
        "token".to_owned(),
    ]
    .into_iter()
    .collect();
    let mut redacted = url.clone();
    if url.query().is_some() {
        let pairs: Vec<_> = url
            .query_pairs()
            .map(|(key, value)| {
                let replacement = if sensitive.contains(&key.to_ascii_lowercase()) {
                    "[REDACTED]".to_owned()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), replacement)
            })
            .collect();
        redacted.query_pairs_mut().clear().extend_pairs(&pairs);
    }
    redacted.to_string()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        NetworkProfile, approve_resolved_destination, connected_peer_is_approved, normalize_url,
        redacted_url, resolve_destination,
    };

    #[test]
    fn normalization_is_reversible_and_removes_only_named_tracking_parameters() {
        let normalized =
            normalize_url("HTTPS://Example.COM/a/../b?utm_source=x&id=7&fbclid=y#fragment")
                .expect("normalize URL");
        assert_eq!(
            normalized.original,
            "HTTPS://Example.COM/a/../b?utm_source=x&id=7&fbclid=y#fragment"
        );
        assert_eq!(normalized.normalized.as_str(), "https://example.com/b?id=7");
        assert_eq!(
            normalized.removed_tracking_parameters,
            ["fbclid", "utm_source"]
        );
    }

    #[test]
    fn unsafe_schemes_user_info_and_ports_fail_closed() {
        assert!(normalize_url("file:///etc/passwd").is_err());
        assert!(normalize_url("https://user:pass@example.com/").is_err());
        assert!(normalize_url("https://example.com:8443/").is_err());
    }

    #[test]
    fn loopback_requires_the_fixture_profile() {
        let url = normalize_url("http://[::1]/")
            .expect("URL syntax is valid")
            .normalized;
        assert!(resolve_destination(&url, NetworkProfile::AutomaticPublic).is_err());
        assert!(resolve_destination(&url, NetworkProfile::FixtureLoopback).is_ok());
    }

    #[test]
    fn injected_dns_answers_cover_mixed_rebinding_and_peer_mismatch() {
        let url = url::Url::parse("https://example.com/path").expect("URL");
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let private = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let approved =
            approve_resolved_destination(&url, NetworkProfile::AutomaticPublic, vec![public])
                .expect("public answer approved");
        assert!(
            approve_resolved_destination(
                &url,
                NetworkProfile::AutomaticPublic,
                vec![public, private]
            )
            .is_err()
        );
        assert!(
            approve_resolved_destination(&url, NetworkProfile::AutomaticPublic, vec![private])
                .is_err()
        );
        assert!(connected_peer_is_approved(
            SocketAddr::new(public, 443),
            &approved
        ));
        assert!(!connected_peer_is_approved(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), 443),
            &approved
        ));
    }

    #[test]
    fn sensitive_query_values_are_redacted() {
        let url = url::Url::parse("https://example.com/?token=secret&id=7").expect("URL");
        assert_eq!(
            redacted_url(&url),
            "https://example.com/?token=%5BREDACTED%5D&id=7"
        );
    }
}
