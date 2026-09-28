import socket
import ssl
import json
import os
import sys
import concurrent.futures
from datetime import datetime, timezone
from typing import Any

import requests

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# ---- Splunk HEC integration -----------------------------------------

SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"
SPLUNK_INDEX = "scan_logs"
SPLUNK_SOURCETYPE = "_json"
SPLUNK_SOURCE = "avlip"
VERIFY_TLS = False  # self-signed local dev cert; use a real CA bundle in production


def get_hec_token() -> str:
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not token:
        sys.exit(
            "ERROR: SPLUNK_HEC_TOKEN environment variable not set.\n"
            "Run: export SPLUNK_HEC_TOKEN='your-token-here'"
        )
    return token


HEC_TOKEN = get_hec_token()  # fail fast, before any scanning starts


def send_to_splunk(event: dict, source: str = SPLUNK_SOURCE) -> bool:
    """Send a single event to Splunk HEC. Silent on success, prints on failure."""
    payload = {
        "event": event,
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX,
        "source": source,
        "time": datetime.now(timezone.utc).timestamp(),
    }
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}

    try:
        resp = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=VERIFY_TLS,
            timeout=5,
        )
    except requests.exceptions.RequestException as exc:
        print(f"  [SPLUNK FAIL] Network error: {exc}")
        return False

    if resp.status_code == 200 and resp.json().get("code") == 0:
        return True

    print(f"  [SPLUNK FAIL] HEC rejected event: {resp.text}")
    return False


# ---- Banner grabbing --------------------------------------------------

def grab_banner(target_ip, port):
    try:
        if port in (80, 8080, 8000, 8443, 8888):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((target_ip, port))
            request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode(errors="ignore")
            s.close()
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return "No Server header returned"

        elif port == 443:
            return grab_https_banner(target_ip, port)

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((target_ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner if banner else "No banner received"

    except Exception as e:
        return f"Could not grab banner: {e}"


def grab_https_banner(target_ip, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(2.5)
        raw_sock.connect((target_ip, port))

        tls_sock = context.wrap_socket(raw_sock, server_hostname=target_ip)

        result: dict[str, Any] = {
            "tls_version": tls_sock.version(),
            "cipher": tls_sock.cipher() if tls_sock.cipher() else "Unknown",
        }

        der_cert = tls_sock.getpeercert(binary_form=True)
        if der_cert:
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            result["certificate_pem_available"] = True
            result["certificate_preview"] = pem_cert.splitlines()[0] + " ... " + pem_cert.splitlines()[-1]
        else:
            result["certificate_pem_available"] = False

        request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(request.encode())
        response = tls_sock.recv(2048).decode(errors="ignore")

        server_header = "No Server header returned"
        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                server_header = line.split(":", 1)[1].strip()
                break
        result["server_header"] = server_header

        tls_sock.close()
        return result

    except Exception as e:
        return f"TLS handshake or HTTPS request failed: {e}"


HIGH_RISK_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900}
MEDIUM_RISK_PORTS = {53, 110, 143, 161, 389, 512, 513, 514, 8080, 8443}


def classify_risk(port):
    if port in HIGH_RISK_PORTS:
        return "High"
    elif port in MEDIUM_RISK_PORTS:
        return "Medium"
    return "Low"


def check_port(target_ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result_code = s.connect_ex((target_ip, port))
    s.close()

    if result_code != 0:
        return None

    severity = classify_risk(port)
    banner = grab_banner(target_ip, port)

    result = {
        "port": port,
        "status": "OPEN",
        "risk_level": severity,
        "alert_triggered": severity == "High",
        "service_banner": banner
    }

    # Stream this port's result to Splunk the moment it's found
    sent = send_to_splunk(result)
    status_tag = "SPLUNK OK" if sent else "SPLUNK FAIL"
    print(f"  [OPEN] Port {port} - {severity} risk ({status_tag})")

    return result


def scan_target(target_ip, port_start=1, port_end=65535, max_workers=300):
    print(f"Starting full port scan on: {target_ip} (ports {port_start}-{port_end})")
    print("This may take a few minutes depending on network conditions...")

    scan_results = {
        "timestamp": datetime.now().isoformat(),
        "target": target_ip,
        "port_range_scanned": f"{port_start}-{port_end}",
        "vulnerabilities_found": []
    }

    ports_to_scan = range(port_start, port_end + 1)
    total = len(ports_to_scan)
    checked = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, target_ip, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            if checked % 5000 == 0:
                print(f"  ...scanned {checked}/{total} ports")
            result = future.result()
            if result:
                scan_results["vulnerabilities_found"].append(result)

    scan_results["vulnerabilities_found"].sort(key=lambda x: x["port"])
    scan_results["total_open_ports"] = len(scan_results["vulnerabilities_found"])
    return scan_results


def read_ssh_banner(target_ip, port=22, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((target_ip, port))
    banner = s.recv(1024).decode(errors="ignore").strip()
    s.close()
    return banner


def send_client_ident(target_ip, port=22, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((target_ip, port))

    server_banner = s.recv(1024).decode(errors="ignore").strip()
    client_ident = "SSH-2.0-ReconClient_1.0\r\n"
    s.sendall(client_ident.encode())

    try:
        response = s.recv(1024)
    except socket.timeout:
        response = b""

    s.close()
    return {
        "server_banner": server_banner,
        "client_sent": client_ident.strip(),
        "response_bytes": response.hex(),
        "response_length": len(response)
    }


def fuzz_test(target_ip, port=22, timeout=2.0):
    payloads = [
        b"\x00" * 50,
        b"A" * 5000,
        b"SSH-99.99-Malformed\r\n",
        b"\xff\xfe\xfd\xfc",
    ]

    results = []
    for payload in payloads:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, port))
            s.recv(1024)
            s.sendall(payload)
            try:
                reply = s.recv(1024)
                status = "responded"
            except socket.timeout:
                reply = b""
                status = "no response (timeout)"
            s.close()
            results.append({
                "payload_preview": payload[:20].hex(),
                "payload_length": len(payload),
                "status": status,
                "reply_length": len(reply)
            })
        except (ConnectionResetError, BrokenPipeError) as e:
            results.append({
                "payload_preview": payload[:20].hex(),
                "payload_length": len(payload),
                "status": f"connection dropped: {e}"
            })
        except Exception as e:
            results.append({
                "payload_preview": payload[:20].hex(),
                "payload_length": len(payload),
                "status": f"error: {e}"
            })

    return results


def attempt_auth(target_ip, port, username, password, timeout=5.0):
    if not PARAMIKO_AVAILABLE:
        return {"status": "paramiko not installed — run: pip install paramiko"}

    client = paramiko.SSHClient()  # type: ignore[union-attr]
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # type: ignore[union-attr]

    try:
        client.connect(
            target_ip, port=port, username=username, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout
        )
        transport = client.get_transport()
        result = {
            "status": "AUTH SUCCESS",
            "username": username,
            "remote_version": transport.remote_version if transport else "unknown"
        }
        client.close()
        return result

    except paramiko.AuthenticationException:  # type: ignore[union-attr]
        return {"status": "AUTH FAILED (bad credentials)", "username": username}
    except (socket.timeout, TimeoutError):
        return {"status": "connection timed out"}
    except Exception as e:
        return {"status": f"error: {e}"}


def ssh_deep_recon(target_ip, port=22, username=None, password=None):
    recon: dict[str, Any] = {
        "target": target_ip,
        "port": port,
        "banner": None,
        "handshake_test": None,
        "fuzz_results": None,
        "auth_attempt": None
    }

    try:
        recon["banner"] = read_ssh_banner(target_ip, port)
    except Exception as e:
        recon["banner"] = f"error: {e}"

    try:
        recon["handshake_test"] = send_client_ident(target_ip, port)
    except Exception as e:
        recon["handshake_test"] = f"error: {e}"

    try:
        recon["fuzz_results"] = fuzz_test(target_ip, port)
    except Exception as e:
        recon["fuzz_results"] = f"error: {e}"

    if username and password:
        recon["auth_attempt"] = attempt_auth(target_ip, port, username, password)
    else:
        recon["auth_attempt"] = "skipped (no credentials provided)"

    # SSH recon is a distinct event type — tag it with its own source
    # so it's easy to filter separately in Splunk: source="avlip-ssh-recon"
    send_to_splunk(recon, source="avlip-ssh-recon")

    return recon


if __name__ == "__main__":
    print(f"Splunk HEC target: {SPLUNK_HEC_URL} (index={SPLUNK_INDEX})")
    print("Each open port found will be streamed to Splunk in real time.\n")

    target = input("Enter target IP address: ").strip()

    mode = input("Scan mode - (f)ull 1-65535 or (q)uick common ports? [f/q]: ").strip().lower()

    if mode == "q":
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
                         993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                         8080, 8443, 8888]
        print(f"Starting quick scan on: {target}")
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities_found": []
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, target, p): p for p in common_ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    scan_results["vulnerabilities_found"].append(result)
        scan_results["vulnerabilities_found"].sort(key=lambda x: x["port"])
        scan_results["total_open_ports"] = len(scan_results["vulnerabilities_found"])
        report = scan_results
    else:
        report = scan_target(target, 1, 65535)

    ssh_open = any(v["port"] == 22 for v in report["vulnerabilities_found"])
    if ssh_open:
        do_deep = input("Port 22 is open. Run deep SSH recon (handshake/fuzz/auth)? (y/n): ").strip().lower()
        if do_deep == "y":
            do_auth = input("Also attempt SSH login? (y/n): ").strip().lower()
            username = password = None
            if do_auth == "y":
                username = input("Username: ").strip()
                password = input("Password: ").strip()
            report["ssh_deep_recon"] = ssh_deep_recon(target, 22, username, password)

    print("\n" + "=" * 50)
    print("FULL SCAN REPORT (also streamed live to Splunk during scan)")
    print("=" * 50)
    print(json.dumps(report, indent=4))
