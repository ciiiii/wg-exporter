mod host;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{Arc, Mutex, RwLock, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ACTIVE_WINDOW: u64 = 180;
const STALE_AFTER: f64 = 90.0;
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn wg(field: &str) -> Result<String, String> {
    // Never call dump/showconf: their output can include private/preshared keys.
    let output = Command::new("timeout")
        .args(["--kill-after=1s", "8s", "wg", "show", "all", field])
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "cannot execute wg".to_string())?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err("wg query failed".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "invalid wg output".into())
}
fn rows(text: &str) -> HashMap<(String, String), Vec<String>> {
    text.lines()
        .filter_map(|line| {
            let mut p = line.split_whitespace();
            Some((
                (p.next()?.into(), p.next()?.into()),
                p.map(String::from).collect(),
            ))
        })
        .collect()
}
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
fn counter_rate(previous: Option<&Value>, field: &str, current: u64, elapsed: f64) -> Option<f64> {
    let old = previous?.get(field)?.as_u64()?;
    if current < old || elapsed <= 0.0 || elapsed > STALE_AFTER {
        None
    } else {
        Some((current - old) as f64 / elapsed)
    }
}
fn build(
    config: &Value,
    previous: &Value,
    timestamp: f64,
    ports: &str,
    allowed: &str,
    handshakes: &str,
    transfers: &str,
) -> Result<(Value, String), String> {
    let hs = rows(handshakes);
    let tx = rows(transfers);
    let addresses = rows(allowed);
    let port_map: HashMap<&str, &str> = ports
        .lines()
        .filter_map(|l| {
            let mut s = l.split_whitespace();
            Some((s.next()?, s.next()?))
        })
        .collect();
    let elapsed = timestamp - previous["collectedAt"].as_f64().unwrap_or(timestamp);
    let mut old_peers = HashMap::new();
    if let Some(items) = previous["wireguard"]["interfaces"].as_array() {
        for iface in items {
            if let Some(peers) = iface["peers"].as_array() {
                for peer in peers {
                    old_peers.insert(
                        (
                            iface["name"].as_str().unwrap_or_default(),
                            peer["publicKey"].as_str().unwrap_or_default(),
                        ),
                        peer,
                    );
                }
            }
        }
    }
    let configured: Vec<String> = if let Some(items) = config["interfaces"].as_array() {
        items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    } else {
        port_map.keys().map(|s| s.to_string()).collect()
    };
    let mut interfaces = Vec::new();
    let mut metrics = String::from(
        "# HELP wireguard_exporter_up Whether WireGuard interface data is available.\n# TYPE wireguard_exporter_up gauge\n# HELP wireguard_peers Configured peers.\n# TYPE wireguard_peers gauge\n# HELP wireguard_active_peers Peers with a handshake in the last 180 seconds.\n# TYPE wireguard_active_peers gauge\n# HELP wireguard_peer_active Recent handshake, not a persistent connection.\n# TYPE wireguard_peer_active gauge\n# HELP wireguard_peer_last_handshake_seconds Last handshake UNIX timestamp, zero if never.\n# TYPE wireguard_peer_last_handshake_seconds gauge\n# HELP wireguard_peer_receive_bytes_total Bytes received since interface/peer creation.\n# TYPE wireguard_peer_receive_bytes_total counter\n# HELP wireguard_peer_transmit_bytes_total Bytes transmitted since interface/peer creation.\n# TYPE wireguard_peer_transmit_bytes_total counter\n",
    );
    for iface in configured {
        let available = port_map.contains_key(iface.as_str());
        let mut peers = Vec::new();
        for ((interface, key), ip) in &addresses {
            if interface != &iface {
                continue;
            }
            let stamp: u64 = hs
                .get(&(iface.clone(), key.clone()))
                .and_then(|v| v.first())
                .ok_or("missing handshake")?
                .parse()
                .map_err(|_| "invalid handshake")?;
            let values = tx
                .get(&(iface.clone(), key.clone()))
                .ok_or("missing transfer")?;
            if values.len() != 2 {
                return Err("invalid transfer".into());
            }
            let rx: u64 = values[0].parse().map_err(|_| "invalid receive counter")?;
            let sent: u64 = values[1].parse().map_err(|_| "invalid transmit counter")?;
            let age = if stamp > 0 {
                Some((timestamp - stamp as f64).max(0.0) as u64)
            } else {
                None
            };
            let active = age.is_some_and(|a| a <= ACTIVE_WINDOW);
            let old = old_peers.get(&(iface.as_str(), key.as_str())).copied();
            let name = config["peerNames"][key].as_str().unwrap_or(key);
            let labels = format!("interface=\"{}\",peer=\"{}\"", escape(&iface), escape(key));
            metrics += &format!(
                "wireguard_peer_active{{{labels}}} {}\nwireguard_peer_last_handshake_seconds{{{labels}}} {stamp}\nwireguard_peer_receive_bytes_total{{{labels}}} {rx}\nwireguard_peer_transmit_bytes_total{{{labels}}} {sent}\n",
                u8::from(active)
            );
            peers.push(json!({"name":name,"publicKey":key,"allowedIps":ip.join(" "),"active":active,"handshakeAgeSeconds":age,"rxBytes":rx,"txBytes":sent,"rxBytesPerSecond":counter_rate(old,"rxBytes",rx,elapsed),"txBytesPerSecond":counter_rate(old,"txBytes",sent,elapsed)}));
        }
        peers.sort_by_key(|p| p["publicKey"].as_str().unwrap_or_default().to_string());
        let active = peers.iter().filter(|p| p["active"] == true).count();
        metrics += &format!(
            "wireguard_exporter_up{{interface=\"{}\"}} {}\n",
            escape(&iface),
            u8::from(available)
        );
        if available {
            metrics += &format!(
                "wireguard_peers{{interface=\"{}\"}} {}\nwireguard_active_peers{{interface=\"{}\"}} {active}\n",
                escape(&iface),
                peers.len(),
                escape(&iface)
            );
        }
        interfaces.push(json!({"name":iface,"available":available,"configuredPeers":peers.len(),"activePeers":active,"peers":peers}));
    }
    metrics += &format!(
        "# TYPE wireguard_exporter_snapshot_timestamp_seconds gauge\nwireguard_exporter_snapshot_timestamp_seconds {timestamp}\n"
    );
    Ok((
        json!({"version":1,"collectedAt":timestamp,"wireguard":{"activeWindowSeconds":ACTIVE_WINDOW,"interfaces":interfaces}}),
        metrics,
    ))
}
struct Snapshot {
    json: Value,
    metrics: String,
    timestamp: f64,
    healthy: bool,
}
fn refresh(config: &Value, previous: &Value) -> Result<(Value, String), String> {
    let timestamp = now();
    let (host, host_metrics) = host::collect(&previous["host"])?;
    let (mut snapshot, mut metrics) = build(
        config,
        previous,
        timestamp,
        &wg("listen-port")?,
        &wg("allowed-ips")?,
        &wg("latest-handshakes")?,
        &wg("transfer")?,
    )?;
    snapshot["host"] = host;
    metrics.push_str(&host_metrics);
    Ok((snapshot, metrics))
}
fn response(request: &[u8], snapshot: &Snapshot) -> (u16, &'static str, Vec<u8>) {
    let first = String::from_utf8_lossy(request);
    let mut fields = first.lines().next().unwrap_or_default().split_whitespace();
    if fields.next() != Some("GET") {
        return (405, "text/plain", b"GET required\n".to_vec());
    }
    let path = fields.next().unwrap_or_default();
    if !matches!(path, "/metrics" | "/stats" | "/healthz") {
        return (404, "text/plain", b"not found\n".to_vec());
    }
    if !snapshot.healthy || now() - snapshot.timestamp > STALE_AFTER {
        return (
            503,
            "text/plain",
            b"WireGuard snapshot unavailable\n".to_vec(),
        );
    }
    match path {
        "/metrics" => (
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            snapshot.metrics.as_bytes().to_vec(),
        ),
        "/stats" => (
            200,
            "application/json",
            serde_json::to_vec(&snapshot.json).unwrap_or_default(),
        ),
        _ => (200, "text/plain", b"ok\n".to_vec()),
    }
}
fn handle(mut stream: TcpStream, shared: &RwLock<Snapshot>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut data = Vec::new();
    let mut buf = [0; 1024];
    while data.len() < 8192 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    if !data.windows(4).any(|w| w == b"\r\n\r\n") {
        return;
    }
    let Ok(snapshot) = shared.read() else {
        return;
    };
    let (code, kind, body) = response(&data, &snapshot);
    drop(snapshot);
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Service Unavailable",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/acck-hk/wg-exporter.json".into());
    let config: Value = serde_json::from_slice(&fs::read(path)?)?;
    let listens = config["listen"].as_array().ok_or("listen array required")?;
    let interval = config["intervalSeconds"]
        .as_u64()
        .unwrap_or(15)
        .clamp(5, 60);
    let mut listeners = Vec::new();
    for addr in listens {
        let addr = addr.as_str().ok_or("invalid listener")?;
        listeners.push(TcpListener::bind(addr)?);
        eprintln!("wg-exporter listening on {addr}");
    }
    let (first, metrics) = refresh(&config, &Value::Null)?;
    let timestamp = first["collectedAt"].as_f64().unwrap_or(0.0);
    let shared = Arc::new(RwLock::new(Snapshot {
        json: first,
        metrics,
        timestamp,
        healthy: true,
    }));
    let poll = Arc::clone(&shared);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(interval));
            let prev = poll.read().map(|s| s.json.clone()).unwrap_or(Value::Null);
            let updated = refresh(&config, &prev);
            if let Ok(mut s) = poll.write() {
                match updated {
                    Ok((body, metrics)) => {
                        s.timestamp = body["collectedAt"].as_f64().unwrap_or(0.0);
                        s.json = body;
                        s.metrics = metrics;
                        s.healthy = true;
                    }
                    Err(_) => {
                        s.healthy = false;
                        eprintln!("WireGuard snapshot refresh failed");
                    }
                }
            }
        }
    });
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(16);
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..4 {
        let queue = Arc::clone(&receiver);
        let data = Arc::clone(&shared);
        thread::spawn(move || {
            loop {
                let connection = match queue.lock() {
                    Ok(q) => q.recv(),
                    Err(_) => return,
                };
                match connection {
                    Ok(stream) => handle(stream, &data),
                    Err(_) => return,
                }
            }
        });
    }
    let mut joins = Vec::new();
    for listener in listeners {
        let tx = sender.clone();
        joins.push(thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = tx.try_send(stream);
            }
        }));
    }
    for join in joins {
        let _ = join.join();
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_never_idle_and_counter_reset() {
        let config = json!({"interfaces":["wg0","missing"],"peerNames":{"key":"Phone"}});
        let (a, m) = build(
            &config,
            &Value::Null,
            1000.0,
            "wg0 51820",
            "wg0 key 10.0.0.2/32",
            "wg0 key 950",
            "wg0 key 100 200",
        )
        .unwrap();
        assert_eq!(a["wireguard"]["interfaces"][0]["activePeers"], 1);
        assert_eq!(a["wireguard"]["interfaces"][1]["available"], false);
        assert!(
            m.contains("wireguard_peer_receive_bytes_total{interface=\"wg0\",peer=\"key\"} 100")
        );
        let (b, _) = build(
            &config,
            &a,
            1030.0,
            "wg0 51820",
            "wg0 key 10.0.0.2/32",
            "wg0 key 0",
            "wg0 key 10 500",
        )
        .unwrap();
        let peer = &b["wireguard"]["interfaces"][0]["peers"][0];
        assert_eq!(peer["active"], false);
        assert!(peer["handshakeAgeSeconds"].is_null());
        assert!(peer["rxBytesPerSecond"].is_null());
        assert_eq!(peer["txBytesPerSecond"], 10.0);
    }
    #[test]
    fn rejects_incomplete_snapshot_and_http_paths() {
        assert!(
            build(
                &json!({}),
                &Value::Null,
                1000.0,
                "wg0 51820",
                "wg0 key 10.0.0.2/32",
                "wg0 key broken",
                ""
            )
            .is_err()
        );
        let snapshot = Snapshot {
            json: json!({}),
            metrics: String::new(),
            timestamp: now(),
            healthy: true,
        };
        assert_eq!(response(b"POST /stats HTTP/1.1\r\n\r\n", &snapshot).0, 405);
        assert_eq!(
            response(b"GET /anything HTTP/1.1\r\n\r\n", &snapshot).0,
            404
        );
        let stale = Snapshot {
            timestamp: now() - 120.0,
            ..snapshot
        };
        assert_eq!(response(b"GET /metrics HTTP/1.1\r\n\r\n", &stale).0, 503);
    }
    #[test]
    fn metric_labels_are_escaped() {
        assert_eq!(escape("a\"\\\nb"), "a\\\"\\\\\\nb");
    }
}
