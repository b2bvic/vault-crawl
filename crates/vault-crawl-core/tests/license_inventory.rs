use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use vault_crawl_core::hash::{is_sha256_hex, sha256_hex};

#[derive(Debug, Deserialize)]
struct Inventory {
    cargo_lock_sha256: String,
    firecrawl_source_copied: bool,
    agpl_code_present: bool,
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    version: String,
    license: String,
    source: String,
}

#[test]
fn license_inventory_covers_every_locked_package() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Inventory = serde_json::from_slice(
        &fs::read(root.join("licenses/dependency-inventory.json"))
            .expect("read dependency inventory"),
    )
    .expect("parse dependency inventory");
    assert!(!inventory.firecrawl_source_copied);
    assert!(!inventory.agpl_code_present);
    assert!(
        inventory
            .packages
            .iter()
            .all(|package| !package.license.trim().is_empty() && package.license != "UNKNOWN")
    );
    assert!(
        inventory
            .packages
            .iter()
            .all(|package| !package.license.to_ascii_uppercase().contains("AGPL"))
    );
    assert!(
        inventory
            .packages
            .iter()
            .all(|package| { matches!(package.source.as_str(), "crates.io" | "workspace") })
    );

    let inventoried: BTreeSet<_> = inventory
        .packages
        .iter()
        .map(|package| (package.name.clone(), package.version.clone()))
        .collect();
    assert_eq!(inventoried.len(), inventory.packages.len());

    let lock = fs::read(root.join("Cargo.lock")).expect("read Cargo.lock");
    assert!(is_sha256_hex(&inventory.cargo_lock_sha256));
    assert_eq!(sha256_hex(&lock), inventory.cargo_lock_sha256);
    let locked = parse_lock_packages(std::str::from_utf8(&lock).expect("Cargo.lock is UTF-8"));
    let locked_sources =
        parse_lock_sources(std::str::from_utf8(&lock).expect("Cargo.lock is UTF-8"));
    assert_eq!(
        inventoried, locked,
        "license inventory and Cargo.lock differ"
    );
    for package in &inventory.packages {
        let key = (package.name.clone(), package.version.clone());
        let locked_source = locked_sources
            .get(&key)
            .expect("inventoried package has lock source record");
        match package.source.as_str() {
            "workspace" => assert!(
                locked_source.is_none(),
                "{key:?} is not a workspace package"
            ),
            "crates.io" => assert!(
                locked_source.as_deref().is_some_and(|source| source
                    .starts_with("registry+https://github.com/rust-lang/crates.io-index")),
                "{key:?} is not a crates.io package"
            ),
            source => panic!("unsupported inventory source {source}"),
        }
    }
}

fn parse_lock_packages(lock: &str) -> BTreeSet<(String, String)> {
    let mut packages = BTreeSet::new();
    let mut name = None;
    let mut version = None;
    for line in lock.lines().chain(["[[package]]"]) {
        if line == "[[package]]" {
            if let (Some(name), Some(version)) = (name.take(), version.take()) {
                packages.insert((name, version));
            }
        } else if let Some(value) = line.strip_prefix("name = \"") {
            name = value.strip_suffix('"').map(str::to_owned);
        } else if let Some(value) = line.strip_prefix("version = \"") {
            version = value.strip_suffix('"').map(str::to_owned);
        }
    }
    packages
}

fn parse_lock_sources(lock: &str) -> BTreeMap<(String, String), Option<String>> {
    let mut packages = BTreeMap::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        let mut source = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("name = \"") {
                name = value.strip_suffix('"').map(str::to_owned);
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = value.strip_suffix('"').map(str::to_owned);
            } else if let Some(value) = line.strip_prefix("source = \"") {
                source = value.strip_suffix('"').map(str::to_owned);
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            packages.insert((name, version), source);
        }
    }
    packages
}
