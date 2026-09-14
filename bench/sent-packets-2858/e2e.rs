use std::{net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}, sync::{Arc, atomic::{AtomicU64, Ordering}}, thread, time::{Duration, Instant}};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::runtime::{Builder, Runtime};
use tracing::error_span;
use tracing::instrument::Instrument as _;
use quinn::{Endpoint, TokioRuntime};

static RECEIVED: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" {
    fn sched_setaffinity(pid: i32, size: usize, mask: *const u8) -> i32;
    fn clock_gettime(id: i32, ts: *mut Timespec) -> i32;
}
#[repr(C)] struct Timespec { sec: i64, nsec: i64 }
fn cpu_time() -> f64 {
    let mut t = Timespec { sec: 0, nsec: 0 };
    assert_eq!(unsafe { clock_gettime(2, &mut t) }, 0);
    t.sec as f64 + t.nsec as f64 * 1e-9
}
fn pin(cpu: usize) {
    let mut mask = [0u8; 128]; mask[cpu / 8] |= 1 << (cpu % 8);
    assert_eq!(unsafe { sched_setaffinity(0, mask.len(), mask.as_ptr()) }, 0);
}
fn bind_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    let requested: usize = std::env::var("SOCKET_BUFFER_BYTES").unwrap_or("0".into()).parse().unwrap();
    let reference = socket2::SockRef::from(&sock);
    if requested != 0 {
        reference.set_recv_buffer_size(requested)?;
        reference.set_send_buffer_size(requested)?;
    }
    eprintln!("SOCKET requested={requested} recv={} send={}", reference.recv_buffer_size()?, reference.send_buffer_size()?);
    Ok(sock)
}
fn iteration(runtime: &Runtime, client: &Arc<quinn::Connection>, data: &'static [u8], concurrent: usize) {
    let mut handles = Vec::with_capacity(concurrent);
    for _ in 0..concurrent {
        let client = client.clone();
        handles.push(runtime.spawn(async move {
            let mut stream = client.open_uni().await.unwrap();
            stream.write_all(data).await.unwrap();
            stream.finish().unwrap();
            assert_eq!(stream.stopped().await.unwrap(), None);
        }));
    }
    runtime.block_on(async { for h in handles { h.await.unwrap(); } });
}
fn main() {
    pin(std::env::var("CLIENT_CPU").unwrap_or("0".into()).parse().unwrap());
    let args: Vec<_> = std::env::args().collect();
    let size: usize = args[1].parse().unwrap();
    let concurrent: usize = args[2].parse().unwrap();
    let seconds: f64 = args.get(3).map(|x| x.parse().unwrap()).unwrap_or(3.0);
    let data: &'static [u8] = Box::leak(vec![0xAB; size].into_boxed_slice());
    let ctx = Context::new();
    let (addr, server) = ctx.spawn_server();
    let (endpoint, client, runtime) = ctx.make_client(addr);
    let client = Arc::new(client);
    let mut all_iterations = 0u64;
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_secs(1) {
        iteration(&runtime, &client, data, concurrent); all_iterations += 1;
    }
    let before = client.stats();
    let mut latencies = Vec::with_capacity(1_000_000);
    let cpu_start = cpu_time();
    let start = Instant::now();
    while start.elapsed().as_secs_f64() < seconds {
        let t = Instant::now();
        iteration(&runtime, &client, data, concurrent);
        latencies.push(t.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let cpu = cpu_time() - cpu_start;
    let after = client.stats();
    let iterations = latencies.len();
    all_iterations += iterations as u64;
    latencies.sort_unstable();
    let bytes = iterations as f64 * size as f64 * concurrent as f64;
    println!("RESULT {{\"size\":{size},\"streams\":{concurrent},\"iterations\":{iterations},\"seconds\":{elapsed},\"mean_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"gbit_s\":{},\"cpu_seconds\":{cpu},\"cpu_ns_byte\":{},\"sent_packets\":{},\"lost_packets\":{}}}", elapsed * 1e9 / iterations as f64, latencies[iterations/2], latencies[iterations*95/100], latencies[iterations*99/100], bytes * 8.0 / elapsed / 1e9, cpu * 1e9 / bytes, after.path.sent_packets - before.path.sent_packets, after.path.lost_packets - before.path.lost_packets);
    client.close(0u32.into(), b"benchmark done");
    drop(client);
    runtime.block_on(endpoint.wait_idle());
    server.join().unwrap();
    assert_eq!(RECEIVED.load(Ordering::Relaxed), all_iterations * size as u64 * concurrent as u64);
}

struct Context {
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
}

impl Context {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let cert = CertificateDer::from(cert.cert);

        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(1024_u16.into());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();

        Self {
            server_config,
            client_config: quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        }
    }

    pub(crate) fn spawn_server(&self) -> (SocketAddr, thread::JoinHandle<()>) {
        let sock = bind_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let addr = sock.local_addr().unwrap();
        let config = self.server_config.clone();
        let handle = thread::spawn(move || {
            pin(std::env::var("SERVER_CPU").unwrap_or("2".into()).parse().unwrap());
            let runtime = rt();
            let endpoint = {
                let _guard = runtime.enter();
                Endpoint::new(
                    Default::default(),
                    Some(config),
                    sock,
                    Arc::new(TokioRuntime),
                )
                .unwrap()
            };
            let handle = runtime.spawn(
                async move {
                    let connection = endpoint
                        .accept()
                        .await
                        .expect("accept")
                        .await
                        .expect("connect");

                    let mut readers = Vec::new();
                    while let Ok(mut stream) = connection.accept_uni().await {
                        readers.push(tokio::spawn(async move {
                            let mut total = 0;
                            while let Some(chunk) = stream.read_chunk(usize::MAX, false).await.unwrap() {
                                total += chunk.bytes.len();
                            }
                            RECEIVED.fetch_add(total as u64, std::sync::atomic::Ordering::Relaxed);
                        }));
                        if readers.len() >= 2048 {
                            for reader in readers.drain(..) { reader.await.unwrap(); }
                        }
                    }
                    for reader in readers { reader.await.unwrap(); }
                }
                .instrument(error_span!("server")),
            );
            runtime.block_on(handle).unwrap();
        });
        (addr, handle)
    }

    pub(crate) fn make_client(
        &self,
        server_addr: SocketAddr,
    ) -> (Endpoint, quinn::Connection, Runtime) {
        let runtime = rt();
        let endpoint = {
            let _guard = runtime.enter();
            Endpoint::new(Default::default(), None, bind_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap(), Arc::new(TokioRuntime)).unwrap()
        };
        let connection = runtime
            .block_on(async {
                endpoint
                    .connect_with(self.client_config.clone(), server_addr, "localhost")
                    .unwrap()
                    .instrument(error_span!("client"))
                    .await
            })
            .unwrap();
        (endpoint, connection, runtime)
    }
}

fn rt() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}
