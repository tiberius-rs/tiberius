//! Tests for `Config::external_authentication`, run against a scripted TDS
//! server on a local socket. No SQL Server is needed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tiberius::{AuthFuture, Client, Config, EncryptionLevel, ExternalAuth, ExternalAuthProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncWriteCompatExt;

const PRELOGIN: u8 = 18;
const LOGIN7: u8 = 16;
const SSPI_TOKEN: u8 = 0xed;
const DONE_TOKEN: u8 = 0xfd;

#[derive(Debug, Default)]
struct Script {
    /// Number of times the provider created a context.
    created: AtomicUsize,
    /// Number of contexts dropped.
    dropped: AtomicUsize,
    /// The SPNs the provider was asked for.
    spns: Mutex<Vec<String>>,
    /// Return an empty initial token.
    empty_initial: bool,
    /// Never report completion.
    endless: bool,
}

#[derive(Debug)]
struct Provider(Arc<Script>);

struct Exchange {
    id: u8,
    script: Arc<Script>,
    complete: bool,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.script.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl ExternalAuthProvider for Provider {
    fn create<'a>(&'a self, spn: &'a str) -> AuthFuture<'a, Box<dyn ExternalAuth>> {
        Box::pin(async move {
            self.0.spns.lock().unwrap().push(spn.to_string());
            let id = self.0.created.fetch_add(1, Ordering::SeqCst) as u8;
            Ok(Box::new(Exchange {
                id,
                script: self.0.clone(),
                complete: false,
            }) as Box<dyn ExternalAuth>)
        })
    }
}

impl ExternalAuth for Exchange {
    fn next_token<'a>(&'a mut self, input: Option<&'a [u8]>) -> AuthFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            match input {
                None if self.script.empty_initial => Ok(Some(Vec::new())),
                None => Ok(Some(vec![9, 8, self.id])),
                Some(server) => {
                    assert_eq!(server, [1, 2, 3]);
                    self.complete = !self.script.endless;
                    Ok(Some(vec![4, 5, self.id]))
                }
            }
        })
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

async fn read_packet(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await.ok()?;
    let mut body = vec![0; u16::from_be_bytes([header[2], header[3]]) as usize - 8];
    stream.read_exact(&mut body).await.ok()?;
    Some((header[0], body))
}

async fn reply(stream: &mut TcpStream, body: &[u8]) {
    let length = (body.len() + 8) as u16;
    let mut packet = vec![4, 1, (length >> 8) as u8, length as u8, 0, 0, 1, 0];
    packet.extend_from_slice(body);
    let _ = stream.write_all(&packet).await;
}

async fn sspi(stream: &mut TcpStream) {
    reply(stream, &[SSPI_TOKEN, 3, 0, 1, 2, 3]).await;
}

/// Answers PRELOGIN and returns the LOGIN7 body.
async fn accept_login(stream: &mut TcpStream) -> Vec<u8> {
    assert_eq!(read_packet(stream).await.unwrap().0, PRELOGIN);
    // Encryption not supported, matching the client below.
    reply(stream, &[1, 0, 6, 0, 1, 255, 2]).await;
    let (kind, login) = read_packet(stream).await.unwrap();
    assert_eq!(kind, LOGIN7);
    login
}

/// A server that accepts one login, issues one SSPI challenge and finishes.
/// Returns the byte the client's final token carried.
async fn serve_login(mut stream: TcpStream) -> u8 {
    let login = accept_login(&mut stream).await;
    assert!(
        login.windows(3).any(|w| w[..2] == [9, 8]),
        "LOGIN7 carries the first token"
    );
    sspi(&mut stream).await;
    let (kind, response) = read_packet(&mut stream).await.unwrap();
    assert_eq!(kind, LOGIN7);
    assert_eq!(response[..2], [4, 5]);
    reply(
        &mut stream,
        &[DONE_TOKEN, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .await;
    response[2]
}

fn config(script: &Arc<Script>) -> Config {
    let mut config = Config::new();
    config.host("db.example.test");
    config.encryption(EncryptionLevel::NotSupported);
    config.external_authentication(Arc::new(Provider(script.clone())));
    config
}

async fn pair() -> (TcpListener, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    (listener, client)
}

#[tokio::test]
async fn login7_and_sspi_round_trip() {
    let script = Arc::new(Script::default());
    let (listener, tcp) = pair().await;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_login(stream).await
    });

    Client::connect(config(&script), tcp.compat_write())
        .await
        .unwrap();

    assert_eq!(server.await.unwrap(), 0);
    assert_eq!(script.created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn default_spn_comes_from_host_and_port() {
    let script = Arc::new(Script::default());
    let (listener, tcp) = pair().await;
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_login(stream).await
    });

    Client::connect(config(&script), tcp.compat_write())
        .await
        .unwrap();

    let spns = script.spns.lock().unwrap();
    assert_eq!(*spns, ["MSSQLSvc/db.example.test:1433"]);
}

#[tokio::test]
async fn spn_override_replaces_the_default() {
    let script = Arc::new(Script::default());
    let mut config = config(&script);
    config.service_principal_name("MSSQLSvc/svc_reader.example.test:1433");
    let (listener, tcp) = pair().await;
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_login(stream).await
    });

    Client::connect(config, tcp.compat_write()).await.unwrap();

    let spns = script.spns.lock().unwrap();
    assert_eq!(*spns, ["MSSQLSvc/svc_reader.example.test:1433"]);
}

#[tokio::test]
async fn cloned_configs_get_separate_contexts() {
    let script = Arc::new(Script::default());
    let config = config(&script);
    let (listener_a, tcp_a) = pair().await;
    let (listener_b, tcp_b) = pair().await;
    let a = tokio::spawn(async move { serve_login(listener_a.accept().await.unwrap().0).await });
    let b = tokio::spawn(async move { serve_login(listener_b.accept().await.unwrap().0).await });

    let (one, two) = tokio::join!(
        Client::connect(config.clone(), tcp_a.compat_write()),
        Client::connect(config, tcp_b.compat_write()),
    );
    one.unwrap();
    two.unwrap();

    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert_ne!(a, b);
    assert_eq!(script.created.load(Ordering::SeqCst), 2);
    assert_eq!(script.dropped.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn empty_initial_token_fails_the_login() {
    let script = Arc::new(Script {
        empty_initial: true,
        ..Script::default()
    });
    let (listener, tcp) = pair().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_packet(&mut stream).await.unwrap().0, PRELOGIN);
        reply(&mut stream, &[1, 0, 6, 0, 1, 255, 2]).await;
    });

    let err = Client::connect(config(&script), tcp.compat_write())
        .await
        .err()
        .unwrap();

    assert!(err.to_string().contains("no initial token"), "{err}");
    assert_eq!(script.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exchange_that_never_completes_fails_after_sixteen_rounds() {
    let script = Arc::new(Script {
        endless: true,
        ..Script::default()
    });
    let (listener, tcp) = pair().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_login(&mut stream).await;
        let mut challenges = 0;
        loop {
            sspi(&mut stream).await;
            challenges += 1;
            if read_packet(&mut stream).await.is_none() {
                return challenges;
            }
        }
    });

    let err = Client::connect(config(&script), tcp.compat_write())
        .await
        .err()
        .unwrap();

    assert!(err.to_string().contains("16 token exchanges"), "{err}");
    assert_eq!(script.dropped.load(Ordering::SeqCst), 1);
    assert!(server.await.unwrap() >= 16);
}

#[tokio::test]
async fn cancelled_login_releases_the_context() {
    let script = Arc::new(Script {
        endless: true,
        ..Script::default()
    });
    let (listener, tcp) = pair().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_login(&mut stream).await;
        // Never answer the LOGIN7, so the client waits for a challenge.
        std::future::pending::<()>().await;
    });

    let login = Client::connect(config(&script), tcp.compat_write());
    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(500), login).await;

    assert!(timed_out.is_err());
    assert_eq!(script.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn setting_an_authentication_method_replaces_the_callback() {
    let script = Arc::new(Script::default());
    let mut config = config(&script);
    config.authentication(tiberius::AuthMethod::sql_server("svc_reader", "unused"));
    assert!(format!("{config:?}").contains("external_auth: None"));
}
