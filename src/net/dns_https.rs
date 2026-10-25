//! RFC 8484 transport using reqwest's HTTP/2 implementation and certificate validation.
use super::{client, config::DohProvider};
use reqwest::blocking::Client;
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{mpsc, Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const TIMEOUT: Duration = Duration::from_millis(2500);

fn source_address(if_index: u32) -> Result<Option<IpAddr>, String> {
    if if_index == 0 {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    super::socket::bind_socket_to_interface(&socket, if_index)?;
    // UDP connect selects a source address; it sends no DNS packet.
    socket.connect("8.8.8.8:443").map_err(|e| e.to_string())?;
    let ip = socket.local_addr().map_err(|e| e.to_string())?.ip();
    if ip.is_unspecified() {
        Err("DoH: исходящий адрес не определён".into())
    } else {
        Ok(Some(ip))
    }
}

fn http_client(provider: &DohProvider, source: Option<IpAddr>) -> Result<Client, String> {
    static CLIENTS: OnceLock<Mutex<HashMap<String, Client>>> = OnceLock::new();
    let key = format!("{}|{:?}|{:?}", provider.url, provider.bootstrap, source);
    let mut clients = CLIENTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|e| e.to_string())?;
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let url = reqwest::Url::parse(&provider.url).map_err(|e| e.to_string())?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("DoH требует HTTPS без credentials".into());
    }
    let host = url.host_str().ok_or("DoH: отсутствует hostname")?;
    let port = url.port_or_known_default().ok_or("DoH: отсутствует порт")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(20));
    if let Some(ip) = source {
        builder = builder.local_address(ip);
    }
    if !provider.bootstrap.is_empty() {
        let addresses: Vec<_> = provider
            .bootstrap
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    let client = builder
        .build()
        .map_err(|e| format!("DoH client: {}", e.without_url()))?;
    if clients.len() >= 32 {
        clients.clear();
    }
    clients.insert(key, client.clone());
    Ok(client)
}

#[cfg(test)]
fn exchange(client: &Client, url: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    exchange_until(client, url, query, Instant::now() + TIMEOUT)
}

fn exchange_until(
    client: &Client,
    url: &str,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or("DoH: deadline expired")?;
    let response = client
        .post(url)
        .timeout(remaining)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .map_err(|e| format!("DoH transport: {}", e.without_url()))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut body = Vec::new();
    response
        .take(65_536)
        .read_to_end(&mut body)
        .map_err(|e| format!("DoH body: {e}"))?;
    validate_answer(query, status, &content_type, &body)?;
    Ok(body)
}

/// Start the system-DNS candidate only after the pinned bootstrap addresses
/// stayed silent for this long. A healthy bootstrap keeps priority and the
/// endpoint name is not leaked to the system resolver on every query.
const SYSTEM_DNS_DELAY: Duration = Duration::from_millis(750);

pub fn query(provider: &DohProvider, query: &[u8], if_index: u32) -> Result<Vec<u8>, String> {
    let source = source_address(if_index)?;
    let query = query.to_vec();
    race_exchanges(
        provider,
        TIMEOUT + Duration::from_millis(100),
        SYSTEM_DNS_DELAY,
        move |candidate, deadline| {
            http_client(&candidate, source)
                .and_then(|client| exchange_until(&client, &candidate.url, &query, deadline))
        },
    )
}

#[derive(Clone, Copy)]
enum Attempt {
    Bootstrap,
    System,
}

fn race_exchanges(
    provider: &DohProvider,
    budget: Duration,
    system_delay: Duration,
    exchange: impl Fn(DohProvider, Instant) -> Result<Vec<u8>, String> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let deadline = started + budget;
    let fallback_at = started + system_delay;
    let exchange = Arc::new(exchange);
    let (tx, rx) = mpsc::channel();
    let start = |attempt, candidate| {
        spawn_exchange(&tx, attempt, candidate, deadline, Arc::clone(&exchange));
    };
    let mut bootstrap_pending = provider.bootstrap.len();
    for ip in &provider.bootstrap {
        let mut candidate = provider.clone();
        candidate.bootstrap = vec![*ip];
        start(Attempt::Bootstrap, candidate);
    }
    let mut system = provider.clone();
    system.bootstrap.clear();
    let mut system_started = bootstrap_pending == 0;
    let mut system_pending = system_started;
    if system_started {
        start(Attempt::System, system.clone());
    }
    let mut bootstrap_error = None;
    let mut system_error = None;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        if !system_started && (bootstrap_pending == 0 || Instant::now() >= fallback_at) {
            // Fast failures need no artificial delay; silent addresses still
            // get the bootstrap preference window. All attempts share a deadline.
            start(Attempt::System, system.clone());
            system_started = true;
            system_pending = true;
        }
        if bootstrap_pending == 0 && !system_pending {
            break;
        }
        let until = if system_started {
            deadline
        } else {
            deadline.min(fallback_at)
        };
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok((_, Ok(answer))) => return Ok(answer),
            Ok((attempt, Err(failure))) => match attempt {
                Attempt::Bootstrap => {
                    bootstrap_pending -= 1;
                    bootstrap_error = Some(failure);
                }
                Attempt::System => {
                    system_pending = false;
                    system_error = Some(failure);
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let timeout = "DoH: deadline expired";
    if provider.bootstrap.is_empty() {
        Err(system_error.unwrap_or_else(|| timeout.into()))
    } else {
        // A bootstrap result can arrive after the system attempt. Tagging the
        // source keeps diagnostics correct regardless of completion order.
        Err(format!(
            "bootstrap: {}; через системный DNS: {}",
            bootstrap_error.as_deref().unwrap_or(timeout),
            system_error.as_deref().unwrap_or(timeout)
        ))
    }
}

fn spawn_exchange(
    tx: &mpsc::Sender<(Attempt, Result<Vec<u8>, String>)>,
    attempt: Attempt,
    provider: DohProvider,
    deadline: Instant,
    exchange: Arc<impl Fn(DohProvider, Instant) -> Result<Vec<u8>, String> + Send + Sync + 'static>,
) {
    let worker_tx = tx.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("antigravity-doh".into())
        .spawn(move || {
            let result = if Instant::now() >= deadline {
                Err("DoH: deadline expired".into())
            } else {
                exchange(provider, deadline)
            };
            let _ = worker_tx.send((attempt, result));
        })
    {
        let _ = tx.send((attempt, Err(format!("DoH worker: {error}"))));
    }
}

fn validate_answer(
    query: &[u8],
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    if status != 200 {
        return Err(format!("DoH HTTP {status}"));
    }
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/dns-message")
    {
        return Err("DoH: неверный Content-Type".into());
    }
    if body.len() > 65_535 || !client::response_matches(query, body) {
        return Err("DoH: ответ не соответствует DNS-запросу".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn provider(bootstrap: bool) -> DohProvider {
        DohProvider {
            name: "test-doh".into(),
            url: "https://resolver.invalid/dns-query".into(),
            bootstrap: if bootstrap {
                vec!["192.0.2.1".parse().unwrap()]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn healthy_bootstrap_does_not_start_a_system_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let answer = race_exchanges(
            &provider(true),
            Duration::from_secs(2),
            Duration::from_secs(1),
            move |candidate, _| {
                assert!(!candidate.bootstrap.is_empty());
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![1, 2, 3])
            },
        )
        .unwrap();
        assert_eq!(answer, [1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_bootstraps_start_fallback_without_waiting_for_the_delay() {
        let answer = race_exchanges(
            &provider(true),
            Duration::from_millis(300),
            Duration::from_secs(2),
            |candidate, _| {
                if candidate.bootstrap.is_empty() {
                    Ok(vec![4, 5, 6])
                } else {
                    Err("retired bootstrap".into())
                }
            },
        )
        .unwrap();
        assert_eq!(answer, [4, 5, 6]);
    }

    #[test]
    fn silent_bootstrap_does_not_prevent_the_system_fallback_from_winning() {
        let started = Instant::now();
        let answer = race_exchanges(
            &provider(true),
            Duration::from_millis(300),
            Duration::from_millis(30),
            |candidate, deadline| {
                if !candidate.bootstrap.is_empty() {
                    std::thread::sleep(Duration::from_millis(450));
                    Err("bootstrap timeout".into())
                } else {
                    // The fallback inherits the original deadline, rather than
                    // starting another full provider budget after the delay.
                    assert!(
                        deadline.saturating_duration_since(Instant::now())
                            < Duration::from_millis(290)
                    );
                    Ok(vec![7, 8, 9])
                }
            },
        )
        .unwrap();
        assert_eq!(answer, [7, 8, 9]);
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn errors_keep_their_source_even_when_bootstrap_finishes_last() {
        let error = race_exchanges(
            &provider(true),
            Duration::from_secs(1),
            Duration::from_millis(10),
            |candidate, _| {
                if candidate.bootstrap.is_empty() {
                    Err("SYSTEM_FAILURE".into())
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                    Err("BOOTSTRAP_FAILURE".into())
                }
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            "bootstrap: BOOTSTRAP_FAILURE; через системный DNS: SYSTEM_FAILURE"
        );
    }

    #[test]
    fn provider_without_bootstrap_runs_only_one_system_attempt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let error = race_exchanges(
            &provider(false),
            Duration::from_secs(1),
            SYSTEM_DNS_DELAY,
            move |candidate, _| {
                assert!(candidate.bootstrap.is_empty());
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Err("system unavailable".into())
            },
        )
        .unwrap_err();
        assert_eq!(error, "system unavailable");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stalled_attempts_share_one_caller_deadline() {
        let started = Instant::now();
        assert!(race_exchanges(
            &provider(true),
            Duration::from_millis(80),
            Duration::from_millis(10),
            |_, _| {
                std::thread::sleep(Duration::from_millis(400));
                Err("too late".into())
            },
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn doh_posts_wire_dns_over_verified_tls_and_checks_the_binary_response() {
        let query = client::build_query("example.test", 71);
        let answer = client::nodata_response(&query);
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len()).into_bytes();
        response.extend_from_slice(&answer);
        let (addr, server) = super::super::health::tests::server(response, Duration::ZERO);
        let cert =
            reqwest::Certificate::from_der(&super::super::health::tests::identity().0).unwrap();
        let client = Client::builder()
            .no_proxy()
            .add_root_certificate(cert)
            .resolve("localhost", addr)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let result = exchange(
            &client,
            &format!("https://localhost:{}/dns-query", addr.port()),
            &query,
        );
        assert_eq!(result.unwrap(), answer);
        server.join().unwrap();
    }
    #[test]
    fn rejects_http_error_wrong_question_transaction_and_oversized_payload() {
        let query = client::build_query("example.test", 42);
        let reply = client::nodata_response(&query);
        assert!(validate_answer(&query, 200, "application/dns-message", &reply).is_ok());
        for (status, mime) in [(503, "application/dns-message"), (200, "text/html")] {
            assert!(validate_answer(&query, status, mime, &reply).is_err());
        }
        let mut wrong = reply.clone();
        wrong[1] ^= 1;
        assert!(validate_answer(&query, 200, "application/dns-message", &wrong).is_err());
        let other = client::nodata_response(&client::build_query("other.test", 42));
        assert!(validate_answer(&query, 200, "application/dns-message", &other).is_err());
        let mut big = reply;
        big.resize(65_536, 0);
        assert!(validate_answer(&query, 200, "application/dns-message", &big).is_err());
    }
}
