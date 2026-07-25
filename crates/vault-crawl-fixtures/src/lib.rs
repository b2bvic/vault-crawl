//! Deterministic, loopback-only fixture server for offline tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Deserialize;
use vault_crawl_core::hash::{is_sha256_hex, sha256_hex};

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureManifest {
    pub schema_version: String,
    pub phase_claim: String,
    pub routes: Vec<FixtureRoute>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureRoute {
    pub path: String,
    pub status: u16,
    pub content_type: String,
    pub file: Option<String>,
    pub body_sha256: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct FixtureServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    /// Starts a deterministic server on an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture manifest is invalid or the loopback
    /// listener cannot be created.
    pub fn start(root: &Path) -> Result<Self, String> {
        let listener = bind_loopback(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("read fixture listener address: {error}"))?;
        let root = root.to_path_buf();
        let manifest = Arc::new(load_manifest(&root)?);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            serve_until_stopped(&listener, &root, &manifest, &thread_stop);
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[must_use]
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/http")
}

/// Loads and validates the fixture route manifest.
///
/// # Errors
///
/// Returns an error for unreadable files, invalid JSON, unsafe paths, or a
/// missing fixture body.
pub fn load_manifest(root: &Path) -> Result<FixtureManifest, String> {
    let path = root.join("manifest.v1.json");
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let manifest: FixtureManifest =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if manifest.schema_version != "1.0.0" || manifest.phase_claim != "phase1-golden-corpus" {
        return Err("fixture manifest must identify the Phase 1 golden corpus".to_owned());
    }
    validate_manifest(root, &manifest)?;
    Ok(manifest)
}

fn validate_manifest(root: &Path, manifest: &FixtureManifest) -> Result<(), String> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize fixture root {}: {error}", root.display()))?;
    let mut paths = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for route in &manifest.routes {
        if !route.path.starts_with('/')
            || route.path.contains("..")
            || route.path.chars().any(char::is_whitespace)
            || route.path.chars().any(char::is_control)
        {
            return Err(format!("unsafe fixture route {}", route.path));
        }
        if !paths.insert(&route.path) {
            return Err(format!("duplicate fixture route {}", route.path));
        }
        if !(100..=599).contains(&route.status) {
            return Err(format!("invalid fixture status {}", route.status));
        }
        if route
            .content_type
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
        {
            return Err(format!("unsafe fixture content type for {}", route.path));
        }
        for (name, value) in &route.headers {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || value
                    .chars()
                    .any(|character| matches!(character, '\r' | '\n'))
            {
                return Err(format!("unsafe fixture header for {}", route.path));
            }
        }
        if !is_sha256_hex(&route.body_sha256) {
            return Err(format!("invalid body SHA-256 for {}", route.path));
        }
        if !hashes.insert(&route.body_sha256) {
            return Err(format!("duplicate fixture body hash for {}", route.path));
        }

        let body = if let Some(file) = &route.file {
            let file_path = Path::new(file);
            if file_path.is_absolute()
                || file_path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(format!("unsafe fixture file {file}"));
            }
            if !files.insert(file) {
                return Err(format!("duplicate fixture file {file}"));
            }
            let candidate = root.join(file);
            let canonical_file = fs::canonicalize(&candidate)
                .map_err(|error| format!("fixture file {file}: {error}"))?;
            if !canonical_file.starts_with(&canonical_root) || !canonical_file.is_file() {
                return Err(format!(
                    "fixture file escapes root or is not regular: {file}"
                ));
            }
            fs::read(&canonical_file)
                .map_err(|error| format!("read fixture file {file}: {error}"))?
        } else {
            Vec::new()
        };
        let actual = sha256_hex(&body);
        if actual != route.body_sha256 {
            return Err(format!(
                "fixture body hash drift for {}: expected {}, got {actual}",
                route.path, route.body_sha256
            ));
        }
    }
    Ok(())
}

/// Binds a fixture listener only when the supplied address is loopback.
///
/// # Errors
///
/// Returns an error for a non-loopback address or listener configuration
/// failure.
pub fn bind_loopback(address: SocketAddr) -> Result<TcpListener, String> {
    if !address.ip().is_loopback() {
        return Err(format!(
            "fixture server refuses non-loopback bind address {}",
            address.ip()
        ));
    }
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("bind fixture server at {address}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set fixture listener nonblocking: {error}"))?;
    Ok(listener)
}

/// Runs the fixture server in the foreground until the process is interrupted.
///
/// # Errors
///
/// Returns an error when the manifest or loopback listener cannot be prepared.
pub fn serve_forever(address: SocketAddr, root: &Path) -> Result<(), String> {
    let manifest = Arc::new(load_manifest(root)?);
    let listener = bind_loopback(address)?;
    let actual = listener
        .local_addr()
        .map_err(|error| format!("read fixture listener address: {error}"))?;
    println!("fixture_server=http://{actual}");
    let stop = AtomicBool::new(false);
    serve_until_stopped(&listener, root, &manifest, &stop);
    Ok(())
}

fn serve_until_stopped(
    listener: &TcpListener,
    root: &Path,
    manifest: &FixtureManifest,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_connection(stream, root, manifest);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    root: &Path,
    manifest: &FixtureManifest,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| format!("set fixture read timeout: {error}"))?;
    let mut buffer = [0_u8; 8192];
    let count = stream
        .read(&mut buffer)
        .map_err(|error| format!("read fixture request: {error}"))?;
    let request = String::from_utf8_lossy(&buffer[..count]);
    let first_line = request.lines().next().unwrap_or_default();
    let mut parts = first_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();

    if !matches!(method, "GET" | "HEAD") {
        return write_response(
            &mut stream,
            405,
            "text/plain",
            &BTreeMap::new(),
            b"method refused",
            method == "HEAD",
        );
    }

    let Some(route) = manifest.routes.iter().find(|route| route.path == path) else {
        return write_response(
            &mut stream,
            404,
            "text/plain",
            &BTreeMap::new(),
            b"fixture not found",
            method == "HEAD",
        );
    };
    let conditional_match = route.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("etag")
            && request.lines().skip(1).any(|line| {
                line.split_once(':').is_some_and(|(header, candidate)| {
                    header.eq_ignore_ascii_case("if-none-match") && candidate.trim() == value
                })
            })
    });
    if conditional_match {
        return write_response(
            &mut stream,
            304,
            &route.content_type,
            &route.headers,
            &[],
            true,
        );
    }
    let body = match &route.file {
        Some(file) => fs::read(root.join(file))
            .map_err(|error| format!("read fixture body {file}: {error}"))?,
        None => Vec::new(),
    };
    write_response(
        &mut stream,
        route.status,
        &route.content_type,
        &route.headers,
        &body,
        method == "HEAD",
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    head_only: bool,
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Fixture",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .and_then(|()| {
            if head_only {
                Ok(())
            } else {
                stream.write_all(body)
            }
        })
        .map_err(|error| format!("write fixture response: {error}"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{bind_loopback, fixture_root, load_manifest, validate_manifest};

    #[test]
    fn phase_one_golden_manifest_and_all_files_exist() {
        let manifest = load_manifest(&fixture_root()).expect("load fixture manifest");
        assert!(manifest.routes.len() >= 12);
        assert_eq!(manifest.phase_claim, "phase1-golden-corpus");
        assert!(
            manifest
                .routes
                .iter()
                .all(|route| route.body_sha256.len() == 64)
        );
    }

    #[test]
    fn body_hash_drift_and_duplicate_routes_are_refused() {
        let root = fixture_root();
        let manifest = load_manifest(&root).expect("load fixture manifest");

        let mut drifted = manifest.clone();
        drifted.routes[0].body_sha256 = "0".repeat(64);
        let error = validate_manifest(&root, &drifted).expect_err("hash drift must fail");
        assert!(error.contains("hash drift"));

        let mut duplicate = manifest;
        duplicate.routes[1].path = duplicate.routes[0].path.clone();
        let error = validate_manifest(&root, &duplicate).expect_err("duplicate route must fail");
        assert!(error.contains("duplicate fixture route"));
    }

    #[test]
    fn non_loopback_bind_is_refused() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(bind_loopback(address).is_err());
    }
}
