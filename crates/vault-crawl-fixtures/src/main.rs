use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use vault_crawl_fixtures::{fixture_root, serve_forever};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fixture_server_refused={error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut root: PathBuf = fixture_root();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bind" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--bind requires an address".to_owned())?;
                bind = value
                    .parse()
                    .map_err(|error| format!("invalid --bind {value}: {error}"))?;
            }
            "--root" => {
                root = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--root requires a path".to_owned())?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "vault-crawl-fixture-server [--bind LOOPBACK:PORT] [--root PATH]\n\
                     Refuses non-loopback bind addresses."
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
    }
    serve_forever(bind, &root)
}
