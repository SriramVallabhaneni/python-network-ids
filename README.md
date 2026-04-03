# Python Network Intrusion Detection System

A Python-based network intrusion detection system (IDS) that monitors live traffic, detects common attacks, and visualizes security metrics through a Grafana dashboard backed by Prometheus.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green)
![Prometheus](https://img.shields.io/badge/Prometheus-latest-orange)
![Grafana](https://img.shields.io/badge/Grafana-latest-red)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)

---

## Features

- **Live packet capture** using Scapy
- **Attack detection** for three common attack types:
  - Port scanning (SYN burst to many ports)
  - SYN flood (DoS via high SYN packet rate)
  - ARP spoofing (MITM via ARP poisoning)
- **Alert system** with structured logging and SQLite persistence
- **Prometheus metrics** exposed at `http://localhost:8000/metrics`
- **Grafana dashboard** with real-time attack visualization
- **Cooldown system** to suppress duplicate alerts per IP

---

## Screenshots
![IDS Dashboard](screenshots/IDS-Dashboard-Screenshot.png)

---

## Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy)
      ↓
Detection Engine
      ↓
Alert System (logs + SQLite)
      ↓
Metrics Exporter (Prometheus)
      ↓
Grafana Dashboard
```

---

## Platform Requirements

**This project requires a native Linux machine or Linux VM.**

`docker-compose.yml` uses `network_mode: host` for the IDS container, which gives it direct access to the host's network interface for raw packet capture. This only works correctly on Linux — on macOS and Windows, Docker runs inside a Hyper-V VM and `network_mode: host` exposes the VM's network rather than the real host interface, making real traffic capture impossible.

**Supported:**
- Linux machine (Ubuntu, Debian, etc.)
- Linux VM (on any host OS)
- AWS EC2 or any Linux cloud instance

**Not supported:**
- macOS (natively)
- Windows (natively)
- WSL2

---

## Detection Rules

| Attack | Method | Threshold |
|---|---|---|
| Port Scan | SYN packets to >20 unique ports in 5s | 20 ports |
| SYN Flood | >100 SYN packets to same target in 5s | 100 packets |
| ARP Spoof | IP→MAC mapping changes unexpectedly | Any change |

Thresholds are configurable in `ids/detector.py`. In production these should be tuned based on your network's normal baseline traffic.

---

## Setup
 
### 1. Clone the repo
 
```bash
git clone https://github.com/yourusername/PacketSentinel.git
cd PacketSentinel
```
 
### 2. Install Docker
 
```bash
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```
 
Log out and back in after adding yourself to the docker group.
 
### 3. Run everything
 
```bash
docker compose up -d --build
```
 
This starts three containers:
- `ids-app` — the IDS sniffer (uses `network_mode: host` for raw packet access)
- `ids-prometheus` — scrapes metrics from the IDS app every 5 seconds
- `ids-grafana` — visualizes metrics from Prometheus
 
Check all three are running:
```bash
docker ps
```
 
Check the IDS app is capturing traffic:
```bash
docker logs ids-app
```
 
---
 
## Grafana Dashboard
 
1. Open `http://<your-ip>:3000`
2. Login with `admin / admin`
3. Go to **Dashboards** → **New** → **Import**
4. Upload `dashboards/ids_dashboard.json`
5. Select **Prometheus** as the datasource
6. Click **Import**
 
Dashboard panels:
- Alert rate over time (time series)
- Total alerts (stat)
- Active attackers (stat)
- Alerts by attack type (stat)
- Port scans by source IP (bar chart)
- SYN floods by source IP (bar chart)
- ARP spoof attempts by source IP (bar chart)
 
---
 
## Testing With Real Attacks
 
The most realistic way to test is using real attack tools from a separate machine on the same network, or from Kali Linux.
 
```bash
# Port scan (triggers PORT_SCAN alert)
sudo nmap -sS -T4 <target-ip>
 
# SYN flood (triggers SYN_FLOOD alert)
sudo hping3 -S --flood -p 80 <target-ip>
 
# ARP spoof (triggers ARP_SPOOF alert)
sudo ettercap -T -M arp:remote /<victim-ip>/ /<gateway-ip>/
```
 
---
 
## Checking Alerts
 
```bash
# View log file
docker exec ids-app cat logs/alerts.log
 
# Query SQLite database
docker exec ids-app sqlite3 data/alerts.db "SELECT * FROM alerts;"
 
# View Prometheus metrics
curl http://localhost:8000/metrics | grep ids_
```
 
---
 
## Configuration
 
Edit thresholds in `ids/detector.py`:
 
```python
PORT_SCAN_THRESHOLD = 20    # unique ports in time window
SYN_FLOOD_THRESHOLD = 100   # SYN packets in time window
TIME_WINDOW = 5             # seconds
COOLDOWN = 60               # in-memory cooldown per IP
DB_COOLDOWN = 300           # database-level cooldown (5 minutes)
```
 
---
 
## Tech Stack
 
| Component | Technology |
|---|---|
| Packet capture | Scapy + libpcap |
| Alert storage | SQLite + Python logging |
| Metrics | Prometheus client |
| Visualization | Grafana |
| Containerization | Docker Compose |
 
---
