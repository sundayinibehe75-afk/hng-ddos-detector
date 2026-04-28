# HNG Stage 3 — Anomaly Detection Engine

> DevSecOps Track | Built in Python

## Live Links
- **Server IP:** `3.223.206.143`
- **Metrics Dashboard:** `http://detector.inibehesunday.online:8080`
- **GitHub Repo:** `https://github.com/sundayinibehe75-afk/hng-ddos-detector`
- **Blog Post:** `<YOUR_BLOG_POST_URL>`

---

## Language Choice

Python — chosen for its readable standard library (`collections.deque`, `threading`, `subprocess`), fast iteration, and excellent ecosystem for this kind of systems tooling. The entire daemon is pure Python with no rate-limiting libraries.

---

## Architecture

```
Internet → Nginx (JSON logs → HNG-nginx-logs volume)
                ↓
         LogMonitor (tail log, parse JSON)
                ↓
         AnomalyDetector (z-score + multiplier check)
           ↙           ↘
      Blocker        Notifier (Slack)
   (iptables DROP)
           ↓
       Unbanner (backoff schedule)
           ↓
       Notifier (Slack unban)

BaselineTracker (rolling 30-min window, recalc every 60s)
Dashboard (Flask, /api/metrics, refreshes every 3s)
```

See `docs/architecture.png` for the visual diagram.

---

## How the Sliding Window Works

Each IP and the global traffic stream each have their own `collections.deque` of **Unix timestamps**.

```python
# On every incoming request:
ip_dq.append(now)                          # record arrival time
cutoff = now - 60                          # 60-second window
while ip_dq and ip_dq[0] < cutoff:        # evict from the LEFT
    ip_dq.popleft()
rate = len(ip_dq) / 60                    # requests per second
```

- Deques are time-ordered (newest on the right).
- Eviction is O(1) amortized — we only pop from the left.
- No counters, no buckets — every timestamp is real.
- The global window works identically but aggregates all IPs.

---

## How the Baseline Works

`BaselineTracker` runs a background thread that:

1. **Every second** — snapshots the per-second request count into a `deque(maxlen=1800)` (30 min × 60 s).
2. **Every 60 seconds** — recalculates `mean` and `stddev` over the rolling window.
3. **Hourly preference** — if the current hour has ≥ 60 samples, it uses only that hour's data (more relevant to current traffic patterns).
4. **Floor values** — `effective_mean = max(mean, 1.0)`, `effective_stddev = max(stddev, 0.5)` prevent division-by-zero and false positives on idle servers.

```python
mean   = sum(samples) / len(samples)
stddev = sqrt(sum((x - mean)**2 for x in samples) / len(samples))
effective_mean   = max(mean, 1.0)
effective_stddev = max(stddev, 0.5)
```

---

## Detection Logic

An IP (or global traffic) is flagged anomalous if **either** condition fires:

| Condition | Formula | Threshold |
|-----------|---------|-----------|
| Z-score   | `(rate - mean) / stddev` | > 3.0 |
| Rate multiplier | `rate / mean` | > 5× |

**Error surge tightening:** If an IP's 4xx/5xx rate exceeds 3× the baseline error rate, both thresholds are multiplied by 0.7 (tighter detection).

---

## Setup — Fresh EC2 to Running Stack

```bash
# 1. SSH into your EC2 instance
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu
newgrp docker

# 3. Install Docker Compose plugin
sudo apt-get install -y docker-compose-plugin

# 4. Clone the repo
git clone <YOUR_GITHUB_REPO_URL>
cd <repo-name>

# 5. Set your environment variables
cp .env.example .env
nano .env   # set EC2_PUBLIC_IP=your.ec2.public.ip

# 6. Set your Slack webhook
nano detector/config.yaml   # set slack.webhook_url

# 7. Start the stack
sudo docker compose up -d

# 8. Verify
sudo docker compose ps
sudo docker compose logs -f detector
```

### EC2 Security Group — Required Inbound Rules

| Port | Protocol | Source    | Purpose              |
|------|----------|-----------|----------------------|
| 22   | TCP      | Your IP   | SSH                  |
| 80   | TCP      | 0.0.0.0/0 | Nginx / Nextcloud    |
| 8080 | TCP      | 0.0.0.0/0 | Detector dashboard   |

The dashboard will be live at `http://detector.inibehesunday.online:8080`.

---

## Repository Structure

```
detector/
  main.py          # entry point, wires threads
  monitor.py       # log tailer + sliding window
  baseline.py      # rolling 30-min baseline
  detector.py      # z-score + multiplier anomaly logic
  blocker.py       # iptables DROP + ban state
  unbanner.py      # backoff unban scheduler
  notifier.py      # Slack webhook alerts
  dashboard.py     # Flask metrics UI
  audit.py         # structured audit log writer
  config.yaml      # all thresholds and settings
  requirements.txt
  Dockerfile
nginx/
  nginx.conf       # JSON access logs, real IP forwarding
docker-compose.yml
docs/
  architecture.png
screenshots/
  tool-running.png
  ban-slack.png
  unban-slack.png
  global-alert-slack.png
  iptables-banned.png
  audit-log.png
  baseline-graph.png
README.md
```

---

## Screenshots

| File | Description |
|------|-------------|
| `screenshots/tool-running.png` | Daemon running, processing log lines |
| `screenshots/ban-slack.png` | Slack ban notification |
| `screenshots/unban-slack.png` | Slack unban notification |
| `screenshots/global-alert-slack.png` | Slack global anomaly alert |
| `screenshots/iptables-banned.png` | `sudo iptables -L -n` showing blocked IP |
| `screenshots/audit-log.png` | Structured audit log entries |
| `screenshots/baseline-graph.png` | Baseline over time (two hourly slots) |

---

## Blog Post

`<YOUR_BLOG_POST_URL>`
