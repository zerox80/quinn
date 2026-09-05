//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, PathBuf},
    str,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use cap_std::{ambient_authority, fs::Dir};
use clap::Parser;
use proto::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tracing::instrument::Instrument as _;
use tracing::{error, info, info_span};

mod common;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,
    /// directory to serve files from
    root: PathBuf,
    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
    /// Client address to block
    #[clap(long = "block")]
    block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    connection_limit: Option<usize>,
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                fs::read(key_path).context("failed to read private key file")?,
            ))
        } else {
            PrivateKeyDer::from_pem_file(key_path)
                .context("failed to read PEM from private key file")?
        };

        let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
            vec![CertificateDer::from(
                fs::read(cert_path).context("failed to read certificate chain file")?,
            )]
        } else {
            CertificateDer::pem_file_iter(cert_path)
                .context("failed to read PEM from certificate chain file")?
                .collect::<Result<_, _>>()
                .context("invalid PEM-encoded certificate")?
        };

        (cert_chain, key)
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok((cert, key)) => (
                CertificateDer::from(cert),
                PrivateKeyDer::try_from(key).map_err(anyhow::Error::msg)?,
            ),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
                let cert = cert.cert.into();
                fs::create_dir_all(path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, key.secret_pkcs8_der())
                    .context("failed to write private key")?;
                (cert, key.into())
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };

        (vec![cert], key)
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let root = Arc::new(
        Dir::open_ambient_dir(&options.root, ambient_authority())
            .context("failed to open root directory")?,
    );
    let connection_slots = options
        .connection_limit
        .map(|limit| Arc::new(Semaphore::new(limit)));

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        if Some(conn.remote_address()) == options.block {
            info!("refusing blocked client IP address");
            conn.refuse();
        } else if options.stateless_retry && !conn.remote_address_validated() {
            info!("requiring connection to validate its address");
            conn.retry().unwrap();
        } else {
            let Ok(permit) = reserve_connection_slot(connection_slots.as_ref()) else {
                info!("refusing due to open connection limit");
                conn.refuse();
                continue;
            };
            info!("accepting connection");
            let fut = handle_connection(root.clone(), conn);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    }

    Ok(())
}

fn reserve_connection_slot(
    slots: Option<&Arc<Semaphore>>,
) -> Result<Option<OwnedSemaphorePermit>, TryAcquireError> {
    slots
        .map(|slots| slots.clone().try_acquire_owned())
        .transpose()
}

async fn handle_connection(root: Arc<Dir>, conn: quinn::Incoming) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(root.clone(), stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    root: Arc<Dir>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!(content = %escaped);
    match parse_get_path(&req) {
        Ok(path) => {
            let mut file = match open_file(root, path).await {
                Ok(file) => file,
                Err(e) => {
                    error!("failed: {}", e);
                    let resp = format!("failed to process request: failed reading file: {e}\n");
                    send.write_all(resp.as_bytes())
                        .await
                        .map_err(|e| anyhow!("failed to send response: {}", e))?;
                    send.finish().unwrap();
                    return Ok(());
                }
            };
            tokio::io::copy(&mut file, &mut send)
                .await
                .map_err(|e| anyhow!("failed to send response: {}", e))?;
        }
        Err(e) => {
            error!("failed: {}", e);
            let resp = format!("failed to process request: {e}\n");
            send.write_all(resp.as_bytes())
                .await
                .map_err(|e| anyhow!("failed to send response: {}", e))?;
        }
    }
    // Gracefully terminate the stream
    send.finish().unwrap();
    info!("complete");
    Ok(())
}

async fn open_file(root: Arc<Dir>, path: PathBuf) -> io::Result<tokio::fs::File> {
    let file = tokio::task::spawn_blocking(move || root.open(path))
        .await
        .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(file.into_std()))
}

fn parse_get_path(x: &[u8]) -> Result<PathBuf> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or(x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;
    let path = path::Path::new(&path);
    let mut relative_path = PathBuf::new();
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => {
                relative_path.push(x);
            }
            x => {
                bail!("illegal component in path: {:?}", x);
            }
        }
    }
    Ok(relative_path)
}

#[cfg(test)]
mod tests {
    use super::{parse_get_path, reserve_connection_slot};
    use cap_std::{ambient_authority, fs::Dir};
    #[cfg(unix)]
    use std::fs;
    use std::{path::PathBuf, sync::Arc};
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    #[test]
    fn connection_slots_are_reserved_until_permits_are_dropped() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = reserve_connection_slot(Some(&slots)).unwrap().unwrap();

        assert!(reserve_connection_slot(Some(&slots)).is_err());
        drop(permit);
        assert!(reserve_connection_slot(Some(&slots)).is_ok());
        assert!(reserve_connection_slot(None).unwrap().is_none());
    }

    #[test]
    fn parses_absolute_paths_relative_to_root() {
        let path = parse_get_path(b"GET /directory/file.txt\r\n").unwrap();

        assert_eq!(path, PathBuf::from("directory").join("file.txt"));
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(parse_get_path(b"GET file.txt\r\n").is_err());
    }

    #[test]
    fn rejects_parent_components() {
        assert!(parse_get_path(b"GET /../file.txt\r\n").is_err());
    }

    #[test]
    fn rejects_missing_files() {
        let dir = tempdir().unwrap();
        let root = Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap();
        let path = parse_get_path(b"GET /missing.txt\r\n").unwrap();

        assert!(root.open(path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_that_escape_root() {
        use std::os::unix::fs::symlink;

        let root_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();
        fs::write(outside_dir.path().join("secret.txt"), b"secret").unwrap();
        symlink(
            outside_dir.path().join("secret.txt"),
            root_dir.path().join("link.txt"),
        )
        .unwrap();
        let root = Dir::open_ambient_dir(root_dir.path(), ambient_authority()).unwrap();
        let path = parse_get_path(b"GET /link.txt\r\n").unwrap();

        assert!(root.open(path).is_err());
    }
}
