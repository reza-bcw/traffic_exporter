/// Network Traffic Monitor & Prometheus Exporter — Production Ready
///
/// Features:
///   - Auto-detects network interface and local IPs
///   - GeoIP via ip-api.com batch API (no key needed)
///   - DDoS detection: SYN_FLOOD, HIGH_PPS, PORT_SCAN, BANDWIDTH_FLOOD
///   - Prometheus metrics at /metrics
///   - Structured JSON logging (tracing)
///   - Graceful shutdown on SIGTERM / SIGINT
///   - Panic-safe RwLock (no poisoned-lock crashes)
///   - Shared HTTP client with timeout + connection pool
///   - ip-api.com rate-limit tracking (15 batch req/min)
///   - systemd-friendly (logs to stdout, exits cleanly)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap::{Capture, Device};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec,
    CounterVec, Encoder, GaugeVec, HistogramVec, TextEncoder,
};
use serde::Serialize;
use tokio::sync::RwLock;         // async-aware, panic-safe RwLock
use tokio::time::interval;
use tracing::{error, info, warn};
use warp::Filter;

// ─── Data Structures ──────────────────────────────────────────────────────────

/// Per-source-IP rolling statistics
#[derive(Debug, Clone)]
struct IpStats {
    packet_count: u64,
    byte_count: u64,
    first_seen: Instant,
    last_seen: Instant,
    /// Unique destination ports — used for port-scan detection
    ports_hit: Vec<u16>,
    /// Bare SYN packet count — used for SYN-flood detection
    syn_count: u64,
    country: String,
    city: String,
}

/// One detected attack event
#[derive(Debug, Clone, Serialize)]
struct DDoSAlert {
    timestamp: u64,
    src_ip: String,
    /// SYN_FLOOD | HIGH_PPS | PORT_SCAN | BANDWIDTH_FLOOD
    attack_type: String,
    pps: f64,
    country: String,
    description: String,
}

/// Shared application state — protected by an async RwLock.
/// Using RwLock (not Mutex) so multiple readers never block each other.
struct AppState {
    ip_stats: HashMap<String, IpStats>,
    /// Rolling window of the last 500 alerts
    alerts: Vec<DDoSAlert>,
    total_packets: u64,
    total_bytes: u64,
    last_window_packets: u64,
    window_start: Instant,
    /// All IPs belonging to this host (inbound/outbound classification)
    local_ips: Vec<String>,
    /// Tracks how many ip-api.com batch calls we've made this minute
    geoip_calls_this_minute: u8,
    geoip_window_start: Instant,
}

impl AppState {
    fn new(local_ips: Vec<String>) -> Self {
        AppState {
            ip_stats: HashMap::new(),
            alerts: Vec::new(),
            total_packets: 0,
            total_bytes: 0,
            last_window_packets: 0,
            window_start: Instant::now(),
            local_ips,
            geoip_calls_this_minute: 0,
            geoip_window_start: Instant::now(),
        }
    }

    /// Returns true if we can make another ip-api.com batch call right now.
    /// Free tier limit: 15 batch requests per minute.
    fn can_geoip(&mut self) -> bool {
        let elapsed = Instant::now().duration_since(self.geoip_window_start);
        if elapsed >= Duration::from_secs(60) {
            // New minute — reset counter
            self.geoip_calls_this_minute = 0;
            self.geoip_window_start = Instant::now();
        }
        self.geoip_calls_this_minute < 14 // stay under 15
    }

    /// Record that one batch call was made
    fn record_geoip_call(&mut self) {
        self.geoip_calls_this_minute += 1;
    }
}

// ─── Auto-Detection ───────────────────────────────────────────────────────────

/// Selects the best capture interface automatically.
/// Order: preferred prefixes (eth/en/wlan…) → any non-loopback → pcap default.
fn auto_detect_interface() -> String {
    if let Ok(devices) = Device::list() {
        for dev in &devices {
            let n = &dev.name;
            if n == "lo" || n.starts_with("loop") { continue; }
            if n.starts_with("eth") || n.starts_with("en")
                || n.starts_with("ens") || n.starts_with("wlan")
                || n.starts_with("wlp") || n.starts_with("bond")
                || n.starts_with("br")
            {
                info!(interface = %n, "Auto-detected network interface");
                return n.clone();
            }
        }
        for dev in &devices {
            if dev.name != "lo" {
                info!(interface = %dev.name, "Using fallback interface");
                return dev.name.clone();
            }
        }
    }
    if let Ok(Some(dev)) = Device::lookup() {
        info!(interface = %dev.name, "Using pcap default interface");
        return dev.name;
    }
    "eth0".to_string()
}

/// Gathers all IP addresses assigned to this host's interfaces.
fn auto_detect_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(devices) = Device::list() {
        for dev in devices {
            for addr in dev.addresses {
                let ip = addr.addr.to_string();
                if !ip.starts_with("127.") && ip != "::1" {
                    ips.push(ip);
                }
            }
        }
    }
    ips.push("127.0.0.1".to_string());
    info!(local_ips = ?ips, "Detected local IP addresses");
    ips
}

// ─── IP Classification ────────────────────────────────────────────────────────

fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
                    || v4.is_broadcast() || v4.is_unspecified() || is_cgnat(v4)
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        }
    } else {
        false
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

// ─── GeoIP ────────────────────────────────────────────────────────────────────

/// Batch-resolves up to 100 IPs via ip-api.com/batch (one HTTP call).
/// Uses a shared reqwest client with a 5-second timeout.
/// Returns ip → (country, city).
async fn geoip_batch(
    ips: &[String],
    client: &reqwest::Client,
) -> HashMap<String, (String, String)> {
    let mut result = HashMap::new();
    if ips.is_empty() { return result; }

    let body: Vec<serde_json::Value> = ips.iter()
        .map(|ip| serde_json::json!({ "query": ip }))
        .collect();

    match client
        .post("http://ip-api.com/batch?fields=status,country,city,query")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<Vec<serde_json::Value>>().await {
                Ok(arr) => {
                    for entry in arr {
                        if entry["status"].as_str() == Some("success") {
                            let ip      = entry["query"].as_str().unwrap_or("").to_string();
                            let country = entry["country"].as_str().unwrap_or("Unknown").to_string();
                            let city    = entry["city"].as_str().unwrap_or("Unknown").to_string();
                            if !ip.is_empty() {
                                result.insert(ip, (country, city));
                            }
                        }
                    }
                    info!(resolved = result.len(), total = ips.len(), "GeoIP batch complete");
                }
                Err(e) => error!(error = %e, "GeoIP batch JSON parse failed"),
            }
        }
        Err(e) => error!(error = %e, "GeoIP batch HTTP request failed"),
    }
    result
}

// ─── Protocol Detection ───────────────────────────────────────────────────────

/// Maps port numbers to application-layer protocol names.
/// Each port appears exactly once to avoid unreachable-pattern compiler warnings.
fn detect_protocol(src_port: u16, dst_port: u16, transport: &str) -> &'static str {
    let uses = |p: u16| src_port == p || dst_port == p;

    if uses(22)    { return "SSH"; }
    if uses(3389)  { return "RDP"; }
    if uses(80)    { return "HTTP"; }
    if uses(443)   { return "HTTPS"; }
    if uses(8080)  { return "HTTP-Alt"; }
    if uses(8443)  { return "HTTPS-Alt"; }
    if uses(53)    { return "DNS"; }
    if uses(25)    { return "SMTP"; }
    if uses(587)   { return "SMTP-TLS"; }
    if uses(993)   { return "IMAPS"; }
    if uses(995)   { return "POP3S"; }
    if uses(21)    { return "FTP"; }
    if uses(3306)  { return "MySQL"; }
    if uses(5432)  { return "PostgreSQL"; }
    if uses(6379)  { return "Redis"; }
    if uses(27017) { return "MongoDB"; }
    if uses(1433)  { return "MSSQL"; }
    if uses(5984)  { return "CouchDB"; }
    if uses(9090)  { return "Prometheus"; }
    if uses(9100)  { return "NodeExporter"; }
    if uses(3000)  { return "Grafana"; }
    if uses(2181)  { return "Zookeeper"; }
    if uses(9092)  { return "Kafka"; }
    if uses(1194)  { return "OpenVPN"; }
    if uses(51820) { return "WireGuard"; }

    match transport {
        "TCP"  => "TCP",
        "UDP"  => "UDP",
        "IPv6" => "IPv6",
        _      => "OTHER",
    }
}

/// Decodes TCP flag bits into a readable string like "SYN|ACK"
fn parse_tcp_flags(tcp: &TcpPacket) -> String {
    let f = tcp.get_flags();
    let mut out = Vec::new();
    if f & 0x02 != 0 { out.push("SYN"); }
    if f & 0x10 != 0 { out.push("ACK"); }
    if f & 0x01 != 0 { out.push("FIN"); }
    if f & 0x04 != 0 { out.push("RST"); }
    if f & 0x08 != 0 { out.push("PSH"); }
    if f & 0x20 != 0 { out.push("URG"); }
    out.join("|")
}

// ─── DDoS Detection ──────────────────────────────────────────────────────────

/// Evaluates one IP against four attack signatures.
///
/// Thresholds (tunable via env vars):
///   SYN_FLOOD       — THRESH_SYN_COUNT SYN packets within first 10 s (default: 500)
///   HIGH_PPS        — THRESH_PPS packets/sec from one IP (default: 1000)
///   PORT_SCAN       — THRESH_PORTS unique destination ports (default: 100)
///   BANDWIDTH_FLOOD — THRESH_MBPS Mbps from one IP (default: 100)
fn check_attack(state: &AppState, src_ip: &str) -> Option<DDoSAlert> {
    // Read thresholds from env at startup (cached by caller ideally, but fine here)
    let thresh_syn: u64   = std::env::var("THRESH_SYN_COUNT").ok().and_then(|v| v.parse().ok()).unwrap_or(500);
    let thresh_pps: f64   = std::env::var("THRESH_PPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000.0);
    let thresh_ports: usize = std::env::var("THRESH_PORTS").ok().and_then(|v| v.parse().ok()).unwrap_or(100);
    let thresh_mbps: f64  = std::env::var("THRESH_MBPS").ok().and_then(|v| v.parse().ok()).unwrap_or(100.0);

    let stats = state.ip_stats.get(src_ip)?;
    let elapsed = Instant::now().duration_since(stats.first_seen).as_secs_f64();
    if elapsed < 1.0 { return None; }

    let pps = stats.packet_count as f64 / elapsed;
    let bps = stats.byte_count   as f64 / elapsed;

    let (kind, desc) = if stats.syn_count >= thresh_syn && elapsed < 10.0 {
        ("SYN_FLOOD", format!("{} SYN pkts in {:.1}s from {}", stats.syn_count, elapsed, src_ip))
    } else if pps > thresh_pps {
        ("HIGH_PPS", format!("{:.0} pkt/s from {}", pps, src_ip))
    } else if stats.ports_hit.len() > thresh_ports {
        ("PORT_SCAN", format!("{} unique ports from {}", stats.ports_hit.len(), src_ip))
    } else if bps > thresh_mbps * 1_000_000.0 {
        ("BANDWIDTH_FLOOD", format!("{:.1} Mbps from {}", bps / 1e6, src_ip))
    } else {
        return None;
    };

    Some(DDoSAlert {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        src_ip: src_ip.to_string(),
        attack_type: kind.to_string(),
        pps,
        country: stats.country.clone(),
        description: desc,
    })
}

// ─── Prometheus Metrics ───────────────────────────────────────────────────────

struct Metrics {
    packets_total:    CounterVec,
    bytes_total:      CounterVec,
    packet_size:      HistogramVec,
    ddos_alerts:      CounterVec,
    top_src_ips:      GaugeVec,
    country_traffic:  CounterVec,
    protocol_packets: CounterVec,
    ssh_attempts:     CounterVec,
    pps_gauge:        GaugeVec,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            packets_total: register_counter_vec!(
                "network_packets_total",
                "Total packets captured, by direction/protocol/country",
                &["direction", "protocol", "country"]
            ).unwrap(),

            bytes_total: register_counter_vec!(
                "network_bytes_total",
                "Total bytes captured, by direction/protocol/country",
                &["direction", "protocol", "country"]
            ).unwrap(),

            packet_size: register_histogram_vec!(
                "network_packet_size_bytes",
                "Packet size distribution",
                &["protocol"],
                vec![64.0, 128.0, 256.0, 512.0, 1024.0, 1500.0]
            ).unwrap(),

            ddos_alerts: register_counter_vec!(
                "ddos_alerts_total",
                "Attack alerts fired, by type and country",
                &["attack_type", "country"]
            ).unwrap(),

            top_src_ips: register_gauge_vec!(
                "network_top_src_ip_packets",
                "Live packet count per source IP",
                &["src_ip", "country", "city"]
            ).unwrap(),

            country_traffic: register_counter_vec!(
                "network_country_packets_total",
                "Packets by country and direction",
                &["country", "direction"]
            ).unwrap(),

            protocol_packets: register_counter_vec!(
                "network_protocol_packets_total",
                "Packets by application protocol",
                &["protocol", "port"]
            ).unwrap(),

            ssh_attempts: register_counter_vec!(
                "ssh_connection_attempts_total",
                "SSH connection attempts by source IP",
                &["src_ip", "country"]
            ).unwrap(),

            pps_gauge: register_gauge_vec!(
                "network_packets_per_second",
                "Current packets per second",
                &["direction"]
            ).unwrap(),
        }
    }
}

// ─── Packet Processing ────────────────────────────────────────────────────────

/// Parses one raw Ethernet frame, updates state + Prometheus counters.
/// Called from the capture thread — must be fast (no async, no allocations beyond needed).
fn process_packet(
    data: &[u8],
    state: &Arc<RwLock<AppState>>,
    metrics: &Arc<Metrics>,
) {
    let eth = match EthernetPacket::new(data) { Some(p) => p, None => return };

    let (src_ip, dst_ip, transport, src_port, dst_port, length, flags) =
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip = match Ipv4Packet::new(eth.payload()) { Some(p) => p, None => return };
                let src = ip.get_source().to_string();
                let dst = ip.get_destination().to_string();
                let len = ip.get_total_length() as usize;
                match ip.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = match TcpPacket::new(ip.payload()) { Some(p) => p, None => return };
                        let fl = parse_tcp_flags(&tcp);
                        (src, dst, "TCP", tcp.get_source(), tcp.get_destination(), len, fl)
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp = match UdpPacket::new(ip.payload()) { Some(p) => p, None => return };
                        (src, dst, "UDP", udp.get_source(), udp.get_destination(), len, String::new())
                    }
                    _ => return,
                }
            }
            EtherTypes::Ipv6 => {
                let ip = match Ipv6Packet::new(eth.payload()) { Some(p) => p, None => return };
                (ip.get_source().to_string(), ip.get_destination().to_string(),
                 "IPv6", 0u16, 0u16, ip.get_payload_length() as usize, String::new())
            }
            _ => return,
        };

    let proto = detect_protocol(src_port, dst_port, transport);
    let is_ssh = proto == "SSH";
    let is_syn = flags.contains("SYN") && !flags.contains("ACK");

    // Use blocking write lock — this is in a dedicated OS thread so it's fine
    let direction;
    let country;
    {
        // Try write lock; if the async runtime holds it briefly, spin-try
        let mut s = state.blocking_write();

        direction = if s.local_ips.contains(&dst_ip) { "inbound" } else { "outbound" };

        s.total_packets += 1;
        s.total_bytes   += length as u64;

        let entry = s.ip_stats.entry(src_ip.clone()).or_insert_with(|| IpStats {
            packet_count: 0,
            byte_count:   0,
            first_seen:   Instant::now(),
            last_seen:    Instant::now(),
            ports_hit:    Vec::new(),
            syn_count:    0,
            country:      "Unknown".to_string(),
            city:         "Unknown".to_string(),
        });

        entry.packet_count += 1;
        entry.byte_count   += length as u64;
        entry.last_seen     = Instant::now();

        if !entry.ports_hit.contains(&dst_port) && entry.ports_hit.len() < 1_000 {
            entry.ports_hit.push(dst_port);
        }
        if is_syn { entry.syn_count += 1; }

        country = entry.country.clone();
    }

    // Update Prometheus counters (outside lock)
    metrics.packets_total.with_label_values(&[direction, proto, &country]).inc();
    metrics.bytes_total.with_label_values(&[direction, proto, &country]).inc_by(length as f64);
    metrics.packet_size.with_label_values(&[proto]).observe(length as f64);
    metrics.protocol_packets.with_label_values(&[proto, &dst_port.to_string()]).inc();
    metrics.country_traffic.with_label_values(&[&country, direction]).inc();
    if is_ssh {
        metrics.ssh_attempts.with_label_values(&[&src_ip, &country]).inc();
    }
}

// ─── Background: DDoS Checker ────────────────────────────────────────────────

/// Runs every 5 s: detection → top-IP gauges → PPS → evict stale IPs
async fn ddos_checker(state: Arc<RwLock<AppState>>, metrics: Arc<Metrics>) {
    let mut tick = interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let mut s = state.write().await;

        // Run attack detection on every tracked IP
        let ips: Vec<String> = s.ip_stats.keys().cloned().collect();
        for ip in &ips {
            if let Some(alert) = check_attack(&s, ip) {
                warn!(
                    attack_type = %alert.attack_type,
                    src_ip = %alert.src_ip,
                    country = %alert.country,
                    desc = %alert.description,
                    "DDoS alert"
                );
                metrics.ddos_alerts.with_label_values(&[&alert.attack_type, &alert.country]).inc();
                if s.alerts.len() >= 500 { s.alerts.remove(0); }
                s.alerts.push(alert);
            }
        }

        // Refresh top-50 source-IP gauges
        let mut sorted: Vec<_> = s.ip_stats.iter().collect();
        sorted.sort_by(|a, b| b.1.packet_count.cmp(&a.1.packet_count));
        for (ip, st) in sorted.iter().take(50) {
            metrics.top_src_ips
                .with_label_values(&[ip, &st.country, &st.city])
                .set(st.packet_count as f64);
        }

        // Update PPS gauge
        let now     = Instant::now();
        let elapsed = now.duration_since(s.window_start).as_secs_f64();
        if elapsed > 0.0 {
            let pps = (s.total_packets - s.last_window_packets) as f64 / elapsed;
            metrics.pps_gauge.with_label_values(&["total"]).set(pps);
            s.last_window_packets = s.total_packets;
            s.window_start        = now;
        }

        // Evict IPs silent for > 5 min to prevent unbounded memory growth
        s.ip_stats.retain(|_, v| {
            Instant::now().duration_since(v.last_seen) < Duration::from_secs(300)
        });
    }
}

// ─── Background: GeoIP Enricher ──────────────────────────────────────────────

/// Runs every 5 s.
/// Batch-resolves all pending "Unknown" IPs in one HTTP call (up to 100 per chunk).
/// Respects the ip-api.com free-tier limit of 15 batch requests per minute.
async fn geo_enricher(state: Arc<RwLock<AppState>>, client: reqwest::Client) {
    let mut tick = interval(Duration::from_secs(5));
    loop {
        tick.tick().await;

        // Snapshot IPs that still need resolution
        let pending: Vec<String> = {
            let s = state.read().await;
            s.ip_stats.iter()
                .filter(|(ip, st)| st.country == "Unknown" && !is_private_ip(ip))
                .map(|(ip, _)| ip.clone())
                .collect()
        };

        if pending.is_empty() { continue; }

        for chunk in pending.chunks(100) {
            // Check rate-limit allowance before each chunk
            let allowed = {
                let mut s = state.write().await;
                if s.can_geoip() {
                    s.record_geoip_call();
                    true
                } else {
                    warn!("GeoIP rate limit reached, skipping this tick");
                    false
                }
            };
            if !allowed { break; }

            let resolved = geoip_batch(&chunk.to_vec(), &client).await;

            let mut s = state.write().await;
            for ip in chunk {
                if let Some((country, city)) = resolved.get(ip) {
                    if let Some(st) = s.ip_stats.get_mut(ip) {
                        st.country = country.clone();
                        st.city    = city.clone();
                    }
                }
            }
        }
    }
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

/// GET /metrics — Prometheus text exposition
async fn h_metrics() -> Result<impl warp::Reply, warp::Rejection> {
    let enc = TextEncoder::new();
    let mut buf = Vec::new();
    enc.encode(&prometheus::gather(), &mut buf).unwrap();
    Ok(warp::reply::with_header(
        String::from_utf8(buf).unwrap(),
        "Content-Type",
        "text/plain; version=0.0.4",
    ))
}

/// GET /alerts — Last 100 DDoS alerts (newest first) as JSON
async fn h_alerts(state: Arc<RwLock<AppState>>) -> Result<impl warp::Reply, warp::Rejection> {
    let s = state.read().await;
    let list: Vec<&DDoSAlert> = s.alerts.iter().rev().take(100).collect();
    Ok(warp::reply::json(&list))
}

/// GET /stats — Global counters + top-20 source IPs as JSON
async fn h_stats(state: Arc<RwLock<AppState>>) -> Result<impl warp::Reply, warp::Rejection> {
    let s = state.read().await;
    let mut top: Vec<serde_json::Value> = s.ip_stats.iter().map(|(ip, st)| {
        serde_json::json!({
            "ip":           ip,
            "packets":      st.packet_count,
            "bytes":        st.byte_count,
            "country":      st.country,
            "city":         st.city,
            "syn_count":    st.syn_count,
            "unique_ports": st.ports_hit.len(),
            "duration_secs": Instant::now().duration_since(st.first_seen).as_secs(),
        })
    }).collect();
    top.sort_by(|a, b| b["packets"].as_u64().unwrap_or(0).cmp(&a["packets"].as_u64().unwrap_or(0)));

    Ok(warp::reply::json(&serde_json::json!({
        "total_packets": s.total_packets,
        "total_bytes":   s.total_bytes,
        "active_ips":    s.ip_stats.len(),
        "total_alerts":  s.alerts.len(),
        "local_ips":     s.local_ips,
        "top_ips":       &top[..top.len().min(20)],
    })))
}

/// GET /health — Liveness probe (used by systemd / load balancers)
async fn h_health() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({ "status": "ok" })),
        warp::http::StatusCode::OK,
    ))
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

/// Waits for SIGTERM or SIGINT (Ctrl-C), then returns so the server can shut down.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c  => info!("Received Ctrl-C, shutting down"),
        _ = sigterm => info!("Received SIGTERM, shutting down"),
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Structured JSON logging — reads RUST_LOG env var (default: info)
    // Set RUST_LOG=debug for verbose output, RUST_LOG=warn for quiet
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()   // JSON lines — compatible with Loki, Datadog, ELK, etc.
        .init();

    info!("Network Traffic Monitor starting");

    // ── Auto-detect everything ────────────────────────────────────────────────
    let iface     = auto_detect_interface();
    let local_ips = auto_detect_local_ips();
    let port: u16 = std::env::var("EXPORTER_PORT")
        .unwrap_or_else(|_| "9999".to_string())
        .parse().unwrap_or(9999);

    info!(
        interface = %iface,
        port      = port,
        thresholds = "SYN>=500 PPS>1000 PORTS>100 BW>100Mbps (override via env)",
        "Configuration"
    );

    // Shared HTTP client with connection pool + timeout (reused for all GeoIP calls)
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(2)
        .user_agent("traffic-exporter/1.0")
        .build()
        .expect("Failed to build HTTP client");

    let state   = Arc::new(RwLock::new(AppState::new(local_ips)));
    let metrics = Arc::new(Metrics::new());

    // Background async tasks
    tokio::spawn(ddos_checker(state.clone(), metrics.clone()));
    tokio::spawn(geo_enricher(state.clone(), http_client));

    // Packet capture in a dedicated OS thread (blocking I/O cannot live in async context)
    let sc       = state.clone();
    let mc       = metrics.clone();
    let if_name  = iface.clone();
    std::thread::spawn(move || {
        let mut cap = Capture::from_device(if_name.as_str())
            .expect("Cannot open capture device — run as root (sudo / CAP_NET_RAW)")
            .promisc(true)   // capture all frames on the wire
            .snaplen(65535)  // full packet, no truncation
            .timeout(100)    // ms between batch reads from kernel
            .open()
            .expect("Failed to activate capture");

        info!(interface = %if_name, "Packet capture started (promiscuous mode)");
        loop {
            match cap.next_packet() {
                Ok(pkt) => process_packet(pkt.data, &sc, &mc),
                Err(pcap::Error::TimeoutExpired) => {} // normal, just try again
                Err(e) => error!(error = %e, "Packet capture error"),
            }
        }
    });

    // HTTP server with graceful shutdown
    let sf = { let s = state.clone(); warp::any().map(move || s.clone()) };

    let routes =
        warp::get().and(warp::path("metrics")).and_then(h_metrics)
        .or(warp::get().and(warp::path("alerts")).and(sf.clone()).and_then(h_alerts))
        .or(warp::get().and(warp::path("stats" )).and(sf.clone()).and_then(h_stats))
        .or(warp::get().and(warp::path("health")).and_then(h_health));

    info!(
        port = port,
        endpoints = "/metrics /alerts /stats /health",
        "HTTP server ready"
    );

    // Bind and serve until shutdown signal
    let (addr, server) = warp::serve(routes)
        .bind_with_graceful_shutdown(([0, 0, 0, 0], port), shutdown_signal());

    info!(bound_addr = %addr, "Listening");
    server.await;

    info!("Shutdown complete");
}
