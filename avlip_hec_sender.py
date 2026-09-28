#!/usr/bin/env python3
"""
avlip_hec_sender.py

Sends AVLIP (Automated Vulnerability & SIEM Log Ingestion Pipeline) scan
results to Splunk via the HTTP Event Collector (HEC) API.

Usage:
    export SPLUNK_HEC_TOKEN="your-token-here"
    python3 avlip_hec_sender.py scan_results_raw.json

Expects input JSON in this shape:
{
    "vulnerabilities_found": [
        {"port": 23, "status": "OPEN", "risk_level": "High", ...},
        ...
    ],
    "total_open_ports": 4
}

Each item in "vulnerabilities_found" is sent as its own Splunk event.
"""

import json
import os
import sys
import requests
from datetime import datetime, timezone

# ---- Configuration -------------------------------------------------

SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"
SPLUNK_INDEX = "scan_logs"
SPLUNK_SOURCETYPE = "_json"
SPLUNK_SOURCE = "avlip"

# Splunk's default cert is self-signed for local dev -> verify=False.
# In production, point this at a real CA bundle instead of disabling verification.
VERIFY_TLS = False


def get_hec_token() -> str:
    """Read the HEC token from environment. Never hardcode it in source."""
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not token:
        sys.exit(
            "ERROR: SPLUNK_HEC_TOKEN environment variable not set.\n"
            "Run: export SPLUNK_HEC_TOKEN='your-token-here'"
        )
    return token


def send_event(event: dict, token: str) -> bool:
    """Send a single event to Splunk HEC. Returns True on success."""
    payload = {
        "event": event,
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX,
        "source": SPLUNK_SOURCE,
        "time": datetime.now(timezone.utc).timestamp(),
    }
    headers = {"Authorization": f"Splunk {token}"}

    try:
        resp = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=VERIFY_TLS,
            timeout=5,
        )
    except requests.exceptions.RequestException as exc:
        print(f"  [FAIL] Network error sending event: {exc}")
        return False

    if resp.status_code == 200 and resp.json().get("code") == 0:
        return True

    print(f"  [FAIL] HEC rejected event (status {resp.status_code}): {resp.text}")
    return False


def load_scan_results(path: str) -> list:
    """Load the scanner's raw JSON output and return the list of vulnerabilities."""
    with open(path, "r") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities_found")
    if vulns is None:
        sys.exit("ERROR: input JSON has no 'vulnerabilities_found' key.")
    return vulns


def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python3 {sys.argv[0]} <scan_results.json>")

    input_path = sys.argv[1]
    token = get_hec_token()
    vulnerabilities = load_scan_results(input_path)

    print(f"Sending {len(vulnerabilities)} events to Splunk (index={SPLUNK_INDEX})...")

    sent, failed = 0, 0
    for vuln in vulnerabilities:
        ok = send_event(vuln, token)
        if ok:
            sent += 1
            print(f"  [OK]   port={vuln.get('port')} risk={vuln.get('risk_level')}")
        else:
            failed += 1

    print(f"\nDone. Sent: {sent}  Failed: {failed}")


if __name__ == "__main__":
    main()
