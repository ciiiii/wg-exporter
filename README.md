# wg-exporter

Native Linux Rust service with cached WireGuard peer and host statistics.
No Docker, Python runtime, database, or private-key output. `wg` and GNU
`timeout` are needed; only public `wg show all` fields are queried.

Endpoints: GET `/metrics` (Prometheus), `/stats` (JSON), `/healthz`.
Snapshots refresh every 15 seconds by default; failed/stale snapshots fail
closed with HTTP 503. Four HTTP workers and a bounded queue serve cached data.

Run: `wg-exporter /etc/acck-hk/wg-exporter.json`.
Config keys: `listen` array of IP:port strings, `interfaces` array, optional
`peerNames` public-key-to-name object, `intervalSeconds` (5–60).
Bind private addresses only. Reading WG needs CAP_NET_ADMIN; deploy with the
systemd sandbox in Workspace `hosts/acck-hk/health/wg-exporter.service`.

WG metrics: interface availability, configured/recent peers, handshake UNIX
timestamps and cumulative RX/TX bytes. Recent means <=180 seconds, not a
persistent connection. JSON also provides per-peer rates with reset detection.

Host metrics are a subset of `node_*`: per-core CPU time, memory in bytes,
load, uptime/boot time, root filesystem capacity/inodes, disk I/O and per-interface
network counters. CPU JSON percentage excludes idle/iowait. Only `/` capacity
is collected. Counters reset on reboot; use `rate()` in Prometheus. Do not sum
physical+tunnel or disk+partition counters as unique traffic.

Build/check:

```sh
cargo test
cargo clippy -- -D warnings
rustup target add x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target x86_64-unknown-linux-musl
```

HK deployment: `/opt/acck-hk/wg-exporter`, service `wg-exporter`, private
listeners `127.0.0.1:9586` and `100.89.81.109:9586`. CT101 Prometheus scrapes
30s; Workspace `iac/grafana/dashboards/acck-hk.json` manages its dashboard.
