use std::io::{Read, Write};
use std::net::TcpStream;

use vault_crawl_fixtures::{FixtureServer, fixture_root};

#[test]
fn local_fixture_server_serves_golden_content() {
    let server = FixtureServer::start(&fixture_root()).expect("start loopback fixture server");
    let mut stream = TcpStream::connect(server.address()).expect("connect to fixture server");
    stream
        .write_all(b"GET /article HTTP/1.1\r\nHost: fixture.local\r\nConnection: close\r\n\r\n")
        .expect("write fixture request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read fixture response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Deterministic Article"));
}

#[test]
fn local_fixture_server_refuses_write_method() {
    let server = FixtureServer::start(&fixture_root()).expect("start loopback fixture server");
    let mut stream = TcpStream::connect(server.address()).expect("connect to fixture server");
    stream
        .write_all(b"POST /article HTTP/1.1\r\nHost: fixture.local\r\nContent-Length: 0\r\n\r\n")
        .expect("write fixture request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read fixture response");
    assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
}
