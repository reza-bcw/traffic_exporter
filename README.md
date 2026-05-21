# Traffic Exporter — Production Setup

## Install dependencies

```bash
sudo apt update
sudo apt install -y libpcap-dev libssl-dev pkg-config build-essential
```

## Build

```bash
cargo build --release
# Binary at: ./target/release/traffic-exporter
```

## Install as systemd service

```bash
# Copy binary
sudo cp target/release/traffic-exporter /usr/local/bin/

# Install service
sudo cp traffic-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-exporter

# View logs
journalctl -u traffic-exporter -f
```

## Endpoints

| URL | Description |
|-----|-------------|
| `http://HOST:9100/metrics` | Prometheus scrape target |
| `http://HOST:9100/alerts`  | DDoS alert log (JSON) |
| `http://HOST:9100/stats`   | Live IP stats (JSON) |
| `http://HOST:9100/health`  | Health check |

## Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: traffic-exporter
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 10s
```

## Environment variables

| Variable           | Default | Description |
|--------------------|---------|-------------|
| `EXPORTER_PORT`    | 9100    | HTTP listen port |
| `RUST_LOG`         | info    | Log level: error/warn/info/debug |
| `THRESH_SYN_COUNT` | 500     | SYN packets before SYN_FLOOD alert |
| `THRESH_PPS`       | 1000    | Packets/sec before HIGH_PPS alert |
| `THRESH_PORTS`     | 100     | Unique ports before PORT_SCAN alert |
| `THRESH_MBPS`      | 100     | Mbps before BANDWIDTH_FLOOD alert |

## Grafana

Import `grafana-dashboard.json` via Grafana → Dashboards → Import.
Set datasource to your Prometheus instance.
