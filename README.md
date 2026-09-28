# AVLIP — Automated Vulnerability & SIEM Log Ingestion Pipeline

A Python-based network reconnaissance and SIEM integration tool. AVLIP performs
concurrent TCP port scanning, protocol-aware service banner grabbing, and TLS
certificate inspection, classifies findings by risk level, and streams results
in real time to Splunk via the HTTP Event Collector (HEC) API.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────┐
│  Port Scanner     │───▶│  Risk Classifier  │───▶│  Splunk HEC       │───▶│ Splunk  │
│  (multithreaded)  │     │  (High/Med/Low)   │     │  (HTTPS, JSON)    │     │  Index  │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └─────────┘
        │
        ▼
┌─────────────────┐
│  Banner Grabbing   │
│  - HTTP headers    │
│  - TLS/cert info    │
│  - SSH banner       │
└─────────────────┘
```

## Features

- **Concurrent port scanning** — configurable thread pool (default 300 workers), full 1–65535 range or a quick common-ports scan
- **Protocol-aware banner grabbing** — HTTP `Server` header extraction, raw TCP banner reads, and full TLS handshake inspection (version, cipher suite, certificate preview) for HTTPS
- **Risk classification** — findings tagged High/Medium/Low based on known-sensitive ports (e.g. Telnet, RDP, database ports)
- **Real-time SIEM streaming** — every discovered port is sent to Splunk immediately via HEC, not batched after the scan completes
- **SSH deep reconnaissance** — optional banner analysis, protocol handshake testing, and malformed-payload fuzz testing against port 22
- **Optional credential testing** — SSH authentication attempt via Paramiko (opt-in, for authorized testing only)

## Requirements

- Python 3.9+
- Splunk Enterprise (or Splunk Cloud) with HTTP Event Collector enabled
- `pip install -r requirements.txt`

## Setup

1. Enable HEC in Splunk: **Settings → Data Inputs → HTTP Event Collector**, create a token, and note its value.
2. Export your token as an environment variable (never hardcode it):
   ```bash
   export SPLUNK_HEC_TOKEN="your-token-here"
   ```
3. Adjust `SPLUNK_HEC_URL`, `SPLUNK_INDEX`, and `SPLUNK_SOURCETYPE` constants at the top of `avlip_scanner_with_splunk.py` if your Splunk instance differs from the local-dev defaults.
4. Run:
   ```bash
   python3 avlip_scanner_with_splunk.py
   ```

## Example Splunk search

Once data is flowing, query it in Splunk:

```
index="scan_logs" source="avlip" risk_level="High"
```

## Legal / Ethical Use

This tool is intended for scanning systems you own or have explicit written
authorization to test. Unauthorized port scanning, banner grabbing, or
credential testing against systems you do not control may violate computer
misuse laws in your jurisdiction. Use only in lab environments, on your own
infrastructure, or with documented permission.

## Roadmap

- [ ] Splunk dashboard for open-port trends by risk level
- [ ] Alerting rule for High-risk findings
- [ ] Scheduled/recurring scan support
- [ ] Multi-target scanning (CIDR range input)
