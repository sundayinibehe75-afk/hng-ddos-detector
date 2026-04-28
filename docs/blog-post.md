# How I Built a Real-Time DDoS Detection Engine for a Cloud Storage Platform

## Introduction

Imagine you're running a cloud storage platform used by thousands of people around the world. Everything is going smoothly until one day, your server starts getting hammered by thousands of requests per second from a single IP address. Your server slows down, legitimate users can't access their files, and your boss is calling.

This is exactly the scenario I was given as a DevSecOps Engineer at HNG's cloud.ng — a Nextcloud-powered cloud storage platform. My job was to build an anomaly detection engine that watches all incoming HTTP traffic in real time, learns what normal looks like, and automatically blocks anything suspicious.

In this post, I'll walk you through how I built it — in plain English, no security experience required.

---

## What the Project Does

The tool sits alongside a Nextcloud server and does five things continuously:

1. **Watches** every HTTP request coming into the server
2. **Learns** what normal traffic looks like over time
3. **Detects** when traffic suddenly spikes beyond normal
4. **Blocks** the offending IP using a firewall rule
5. **Alerts** the team on Slack and shows a live dashboard

Think of it like a security guard who studies the normal flow of people entering a building, then raises an alarm and locks the door when someone starts rushing in suspiciously fast.

---

## The Stack

- **Python** — the detection daemon
- **Nginx** — reverse proxy that logs all incoming requests in JSON format
- **Docker Compose** — runs everything together
- **iptables** — Linux firewall used to block malicious IPs
- **Flask** — serves the live metrics dashboard
- **Slack** — sends real-time alerts

---

## How the Sliding Window Works

The first challenge is: how do you measure how fast requests are coming in?

A naive approach would be to count requests per minute. But that's too slow — a DDoS attack can flood your server in seconds.

Instead, I used a **sliding window** — a rolling 60-second view of recent requests. Here's how it works:

Every time a request comes in, I record the current timestamp into a `deque` (a double-ended queue — think of it as a list you can add to on the right and remove from the left efficiently).

```python
from collections import deque
import time

ip_window = deque()  # one per IP address
global_window = deque()  # one for all traffic combined

def on_request(ip):
    now = time.time()
    
    # Add this request's timestamp
    ip_window.append(now)
    global_window.append(now)
    
    # Evict timestamps older than 60 seconds from the LEFT
    cutoff = now - 60
    while ip_window and ip_window[0] < cutoff:
        ip_window.popleft()
    
    # Rate = number of requests in the last 60 seconds / 60
    rate = len(ip_window) / 60  # requests per second
```

The key insight: the deque is always time-ordered (newest on the right). So evicting old entries is just popping from the left until we hit something recent. This is O(1) — extremely fast.

I maintain two windows:
- **Per-IP window** — tracks how fast a single IP is sending requests
- **Global window** — tracks the overall traffic rate across all IPs

---

## How the Baseline Learns from Traffic

Detecting anomalies requires knowing what "normal" looks like. I can't hardcode a number like "100 requests/second is too many" — that would be wrong for a busy server at peak hours and overly sensitive at 3am.

Instead, I built a **rolling baseline** that learns from the last 30 minutes of traffic.

Every second, I record how many requests came in during that second. I store up to 1800 of these values (30 minutes × 60 seconds) in a rolling deque.

Every 60 seconds, I calculate:
- **Mean** — the average requests per second over the last 30 minutes
- **Standard deviation** — how much the traffic normally varies

```python
import math

samples = [count_per_second_1, count_per_second_2, ...]  # last 30 mins

mean = sum(samples) / len(samples)
variance = sum((x - mean) ** 2 for x in samples) / len(samples)
stddev = math.sqrt(variance)

# Apply a floor so we never divide by zero on idle servers
effective_mean = max(mean, 1.0)
effective_stddev = max(stddev, 0.5)
```

I also maintain **per-hour slots** — separate baselines for each clock hour. If the current hour has enough data (at least 60 samples), I prefer it over the full 30-minute window. This means the baseline adapts to time-of-day patterns — peak hours get a higher baseline, quiet hours get a lower one.

---

## How the Detection Logic Makes a Decision

With a baseline established, detecting anomalies becomes a statistics problem. I use two triggers — whichever fires first wins:

### Trigger 1 — Z-Score
The z-score measures how many standard deviations above normal the current rate is:

```python
zscore = (current_rate - mean) / stddev
```

If the z-score exceeds **3.0**, the traffic is statistically anomalous. In a normal distribution, only 0.3% of values fall beyond 3 standard deviations — so this is a strong signal.

### Trigger 2 — Rate Multiplier
If the current rate is more than **5 times** the baseline mean, it's flagged regardless of z-score. This catches sudden spikes on servers with very stable traffic where stddev is tiny.

```python
if zscore > 3.0 or current_rate > 5 * mean:
    # Anomaly detected!
    block(ip)
```

### Error Surge Tightening
If an IP is also sending lots of bad requests (4xx/5xx errors) — more than 3 times the normal error rate — I tighten the thresholds by 30%. This catches slower, more careful attackers who try to stay just below the detection threshold.

---

## How iptables Blocks an IP

Once an anomaly is detected, I need to stop that IP from sending any more traffic. I use **iptables** — Linux's built-in firewall.

iptables works by processing network packets through a set of rules. I insert a DROP rule at the top of the INPUT chain:

```python
import subprocess

def block_ip(ip):
    subprocess.run([
        "iptables", "-I", "INPUT",   # Insert at top of INPUT chain
        "-s", ip,                     # Source IP to block
        "-j", "DROP"                  # Action: silently drop the packet
    ])
```

`-j DROP` means the packet is silently discarded — the attacker gets no response, which is better than `REJECT` (which tells them the port is closed).

The rule sits at the top of the chain, so it's checked before any ACCEPT rules. The blocked IP's packets never reach Nginx or Nextcloud.

### Auto-Unban with Backoff
Bans aren't permanent by default. I use a backoff schedule:
- 1st offence → 10 minutes
- 2nd offence → 30 minutes  
- 3rd offence → 2 hours
- 4th offence → permanent

This gives legitimate users who accidentally triggered the detector a chance to get back in, while repeat offenders get progressively longer bans.

---

## The Live Dashboard

I built a Flask web dashboard that refreshes every 3 seconds showing:
- Global requests per second
- Baseline mean and standard deviation
- Currently banned IPs and when they expire
- Top 10 source IPs
- CPU and memory usage
- System uptime

This gives the security team a real-time view of what's happening without having to SSH into the server.

---

## Lessons Learned

- **Don't hardcode thresholds** — traffic patterns change by hour, day, and season. A dynamic baseline is essential.
- **Sliding windows beat counters** — per-minute counters miss burst attacks. Timestamp-based deques give you second-level precision.
- **iptables is powerful but careful** — blocking the wrong IP can lock out legitimate users. The z-score threshold of 3.0 keeps false positives very low.
- **Structured logging matters** — every ban, unban, and baseline recalculation is written to an audit log. When something goes wrong, you need a paper trail.

---

## Conclusion

Building this project taught me that security tooling doesn't have to be magic. At its core, DDoS detection is just statistics — measure what's normal, flag what isn't, and respond automatically.

The full source code is available on GitHub: [https://github.com/sundayinibehe75-afk/hng-ddos-detector](https://github.com/sundayinibehe75-afk/hng-ddos-detector)

If you're learning DevSecOps, I hope this breakdown helps demystify how real-world anomaly detection works under the hood.
