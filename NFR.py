#!/usr/bin/env python3
"""
NFR - NEED FOR RACE
Master HTTP Race Condition & Concurrency Testing Framework
Features: HTTP/2 Single-Packet Attack (Last-Byte Sync), Multi-Session Rotation,
Baseline Differential Anomaly Engine, Rich TUI, HTML/JSON/SARIF Reporting.
"""

import asyncio
import argparse
import sys
import time
import random
import uuid
import math
import json
import os
import re
import ssl
import hashlib
import datetime
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Union

import yaml
import httpx
from colorama import init, Fore, Style

# Try importing rich for TUI
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich.color import Color
    has_rich = True
except ImportError:
    has_rich = False

# Try importing tqdm for progress bar
try:
    from tqdm import tqdm
    has_tqdm = True
except ImportError:
    has_tqdm = False

# Try importing h2 for HTTP/2 single-packet last-byte synchronization
try:
    import h2.connection
    import h2.events
    import h2.config
    has_h2 = True
except ImportError:
    has_h2 = False

init(autoreset=True)
console = Console() if has_rich else None

# COLOR & FORMATTING UTILITIES

def color_status(status_code: int) -> str:
    if 200 <= status_code < 300:
        return f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
    elif 300 <= status_code < 400:
        return f"{Fore.YELLOW}{status_code}{Style.RESET_ALL}"
    elif 400 <= status_code < 500:
        return f"{Fore.RED}{status_code}{Style.RESET_ALL}"
    elif status_code >= 500:
        return f"{Fore.MAGENTA}{status_code}{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}ERROR{Style.RESET_ALL}"

def print_startup_error(stage: str, title: str, details: str, hint: Optional[str] = None):
    """Prints a clear, visible error card in the console."""
    print("=" * 60)
    print(f"{Fore.RED}{Style.BRIGHT}ERROR: [{stage}] - {title}{Style.RESET_ALL}")
    print("-" * 60)
    print(f"{Fore.YELLOW}Details:{Style.RESET_ALL}")
    print(f"  {details}")
    if hint:
        print()
        print(f"{Fore.GREEN}Hint/Suggestion:{Style.RESET_ALL}")
        print(f"  {hint}")
    print("=" * 60)

def friendly_network_error(e: Exception, timeout: float) -> str:
    """Translates generic network exceptions into human-readable explanations."""
    if isinstance(e, httpx.ConnectTimeout):
        return "Connection Timeout (Failed to establish TCP/TLS connection)"
    elif isinstance(e, httpx.ReadTimeout):
        return f"Read Timeout (Server failed to respond within {timeout}s)"
    elif isinstance(e, httpx.WriteTimeout):
        return f"Write Timeout (Failed to send request bytes within {timeout}s)"
    elif isinstance(e, httpx.ConnectError):
        return "Connection Error (Target host is unreachable or DNS resolution failed)"
    elif isinstance(e, httpx.RemoteProtocolError):
        return "Protocol Error (Server closed connection prematurely or sent invalid HTTP bytes)"
    elif isinstance(e, httpx.InvalidURL):
        return "Invalid Target URL Format"
    elif isinstance(e, httpx.LocalProtocolError):
        return "Local Protocol Error (Invalid client HTTP state)"
    elif isinstance(e, httpx.ProxyError):
        return "Proxy Error (Failed to connect through configured proxy)"
    else:
        return f"Request Error: {e}"

# DYNAMIC TEMPLATE & EXPRESSION EVALUATION ENGINE

def generate_random_ip() -> str:
    """Generates a random valid IPv4 address."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def render_template(val: Any, idx: int, payload: str = "", session_info: Optional[Dict[str, Any]] = None) -> Any:
    """
    Recursively evaluates dynamic template tags in request configs.
    Supports both {{tag}} and ${expression} syntax.
    Built-in tags & expressions:
      - {{payload}} / ${payload}
      - {{random_int}} / ${random_int()} / ${math.random()}
      - {{timestamp}} / ${timestamp()}
      - ${time.now_iso()}
      - {{uuid}} / ${uuid()}
      - {{index}} / {{seq}} / ${index()} / ${seq()}
      - {{random_str:N}} / ${random_str(N)}
      - ${hash.sha256(val)} / ${hash.md5(val)}
      - ${random_ip()}
      - {{urlencode(...)}}
    """
    if isinstance(val, str):
        res = val

        # 1. Payload substitution
        if "{{payload}}" in res:
            res = res.replace("{{payload}}", payload)
        if "${payload}" in res:
            res = res.replace("${payload}", payload)

        # 2. Session info substitution if provided
        if session_info:
            for s_key, s_val in session_info.items():
                tag = f"{{{{session.{s_key}}}}}"
                tag2 = f"${{session.{s_key}}}"
                if tag in res:
                    res = res.replace(tag, str(s_val))
                if tag2 in res:
                    res = res.replace(tag2, str(s_val))

        # 3. Random Int
        while "{{random_int}}" in res:
            res = res.replace("{{random_int}}", str(random.randint(100000, 999999)), 1)
        while "${random_int()}" in res:
            res = res.replace("${random_int()}", str(random.randint(100000, 999999)), 1)
        while "${math.random()}" in res:
            res = res.replace("${math.random()}", str(random.randint(100000, 999999)), 1)

        # 4. Timestamp
        while "{{timestamp}}" in res:
            res = res.replace("{{timestamp}}", str(int(time.time() * 1000)), 1)
        while "${timestamp()}" in res:
            res = res.replace("${timestamp()}", str(int(time.time() * 1000)), 1)
        while "${time.now_iso()}" in res:
            res = res.replace("${time.now_iso()}", datetime.datetime.now(datetime.timezone.utc).isoformat(), 1)

        # 5. UUID
        while "{{uuid}}" in res:
            res = res.replace("{{uuid}}", str(uuid.uuid4()), 1)
        while "${uuid()}" in res:
            res = res.replace("${uuid()}", str(uuid.uuid4()), 1)

        # 6. Index & Sequence
        if "{{index}}" in res:
            res = res.replace("{{index}}", str(idx))
        if "{{seq}}" in res:
            res = res.replace("{{seq}}", str(idx))
        if "${index()}" in res:
            res = res.replace("${index()}", str(idx))
        if "${seq()}" in res:
            res = res.replace("${seq()}", str(idx))

        # 7. Random String length N
        if "{{random_str:" in res:
            matches = re.findall(r"\{\{random_str:(\d+)\}\}", res)
            for m in matches:
                length = int(m)
                rand_s = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))
                res = res.replace(f"{{{{random_str:{m}}}}}", rand_s, 1)

        if "${random_str(" in res:
            matches = re.findall(r"\$\{random_str\((\d+)\)\}", res)
            for m in matches:
                length = int(m)
                rand_s = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))
                res = res.replace(f"${{random_str({m})}}", rand_s, 1)

        # 8. Random IP address (for X-Forwarded-For rotation)
        while "${random_ip()}" in res:
            res = res.replace("${random_ip()}", generate_random_ip(), 1)

        # 9. Hash functions: ${hash.sha256(...)} and ${hash.md5(...)}
        if "${hash.sha256(" in res:
            matches = re.findall(r"\$\{hash\.sha256\((.*?)\)\}", res)
            for m in matches:
                # Evaluate inner value if it matches index or sequence
                target_val = str(idx) if m in ("index", "seq", "idx") else m
                h_val = hashlib.sha256(target_val.encode()).hexdigest()
                res = res.replace(f"${{hash.sha256({m})}}", h_val, 1)

        if "${hash.md5(" in res:
            matches = re.findall(r"\$\{hash\.md5\((.*?)\)\}", res)
            for m in matches:
                target_val = str(idx) if m in ("index", "seq", "idx") else m
                h_val = hashlib.md5(target_val.encode()).hexdigest()
                res = res.replace(f"${{hash.md5({m})}}", h_val, 1)

        # 10. URL encoding wrapper: {{urlencode(...)}}
        if "{{urlencode(" in res:
            while True:
                start_idx = res.find("{{urlencode(")
                if start_idx == -1:
                    break
                end_idx = res.find(")}}", start_idx)
                if end_idx == -1:
                    break
                content = res[start_idx + len("{{urlencode("):end_idx]
                encoded = urllib.parse.quote(content)
                res = res[:start_idx] + encoded + res[end_idx + 3:]

        return res
    elif isinstance(val, dict):
        return {k: render_template(v, idx, payload, session_info) for k, v in val.items()}
    elif isinstance(val, list):
        return [render_template(v, idx, payload, session_info) for v in val]
    return val

# INPUT LOADERS & PARSERS

def load_wordlist(path: str) -> List[str]:
    """Loads a payload wordlist file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            words = [line.strip() for line in f if line.strip()]
        if not words:
            raise ValueError("Wordlist is empty")
        return words
    except Exception as e:
        raise RuntimeError(f"Failed to read wordlist: {e}")

def load_sessions(path: str) -> List[Dict[str, Any]]:
    """
    Loads session pool from file (.txt, .json, or .yaml).
    Returns list of session dictionaries (e.g., {"headers": {...}, "cookies": {...}}).
    """
    if not os.path.exists(path):
        raise RuntimeError(f"Sessions file not found: {path}")

    sessions = []
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        sessions.append({"Authorization": item} if "bearer" in item.lower() or "token" in item.lower() else {"Cookie": item})
                    elif isinstance(item, dict):
                        sessions.append(item)
    elif path.endswith(".yaml") or path.endswith(".yml"):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        sessions.append(item)
    else:
        # Plain text file (one token or cookie string per line)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
            for line in lines:
                if line.lower().startswith("authorization:") or line.lower().startswith("cookie:"):
                    k, v = line.split(":", 1)
                    sessions.append({k.strip(): v.strip()})
                elif "bearer " in line.lower() or "token " in line.lower():
                    sessions.append({"Authorization": line})
                else:
                    sessions.append({"Cookie": line})

    if not sessions:
        raise ValueError("No valid session entries found in sessions file.")
    return sessions

def parse_raw_request(file_path: str, force_http: bool = False) -> Dict[str, Any]:
    """Parses a raw HTTP request (e.g. from Burp Suite) into a configuration dictionary."""
    with open(file_path, "rb") as f:
        content_bytes = f.read()

    double_crlf = b"\r\n\r\n"
    double_lf = b"\n\n"

    if double_crlf in content_bytes:
        header_part, body_bytes = content_bytes.split(double_crlf, 1)
    elif double_lf in content_bytes:
        header_part, body_bytes = content_bytes.split(double_lf, 1)
    else:
        header_part = content_bytes
        body_bytes = b""

    header_str = header_part.decode("utf-8", errors="replace")
    header_lines = header_str.splitlines()
    if not header_lines:
        raise ValueError("Raw request header section is empty")

    req_line = header_lines[0].strip()
    first_space = req_line.find(" ")
    if first_space == -1:
        raise ValueError(f"Invalid HTTP request line: '{req_line}'")

    method = req_line[:first_space].strip()
    last_space = req_line.rfind(" ")

    if last_space != first_space:
        last_word = req_line[last_space:].strip()
        if last_word.upper().startswith("HTTP/"):
            path = req_line[first_space:last_space].strip()
        else:
            path = req_line[first_space:].strip()
    else:
        path = req_line[first_space:].strip()

    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    body_str = None
    if body_bytes:
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            body_str = body_bytes.decode("latin-1")

    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        host = headers.get("Host") or headers.get("host")
        if not host:
            raise ValueError("Host header not found in raw request and path is not an absolute URL")

        protocol = "http" if force_http else "https"
        if not force_http and ":80" in host:
            protocol = "http"

        if not path.startswith("/"):
            path = "/" + path
        url = f"{protocol}://{host}{path}"

    req_dict = {
        "method": method,
        "url": url,
        "headers": headers,
    }

    if body_str:
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""
        if "application/json" in content_type:
            try:
                req_dict["body"] = json.loads(body_str)
            except Exception:
                req_dict["body"] = body_str
        else:
            req_dict["body"] = body_str

    return req_dict

def load_yaml(yaml_path: str) -> Dict[str, Any]:
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("YAML file must represent a dictionary structure")
    if 'method' not in data or 'url' not in data:
        raise ValueError("YAML file must contain 'method' and 'url' keys")
    return data

# STATISTICAL & DIFFERENTIAL ANOMALY ENGINE

def calculate_percentiles(durations: List[float]) -> Dict[str, float]:
    if not durations:
        return {}
    sorted_durations = sorted(durations)
    n = len(sorted_durations)

    def get_p(p: float) -> float:
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_durations[int(k)]
        return sorted_durations[f] * (c - k) + sorted_durations[c] * (k - f)

    return {
        "min": sorted_durations[0],
        "max": sorted_durations[-1],
        "avg": sum(sorted_durations) / n,
        "p50": get_p(0.50),
        "p90": get_p(0.90),
        "p95": get_p(0.95),
        "p99": get_p(0.99)
    }

def analyze_differential_anomalies(
    results: List[Dict[str, Any]],
    baseline_result: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Automated Differential Engine:
    Compares race burst results against baseline (N=1) and cohort statistics to flag:
      1. Duplicate Successes (multiple 2xx status codes)
      2. Response Length Outliers (>10% deviation from baseline/modal length)
      3. Database Lock Timeouts (duration spikes >3x baseline or 500/504 errors)
    """
    anomalies = []
    total = len(results)
    if total == 0:
        return anomalies

    # 1. Check for Duplicate Successes
    successes = [r for r in results if r.get("status_code", 0) and 200 <= r["status_code"] < 300]
    if len(successes) > 1:
        anomalies.append({
            "type": "DUPLICATE_SUCCESSES",
            "title": "Multiple Concurrent Successes Detected",
            "severity": "HIGH",
            "details": f"{len(successes)} requests returned HTTP 2xx success status codes concurrently.",
            "affected_indices": [r["index"] for r in successes]
        })

    # 2. Check for Response Length Outliers
    if baseline_result and baseline_result.get("length"):
        base_len = baseline_result["length"]
        outlier_reqs = []
        for r in results:
            if r.get("length"):
                dev = abs(r["length"] - base_len) / base_len if base_len > 0 else 0
                if dev > 0.10:  # > 10% deviation
                    outlier_reqs.append((r["index"], r["length"], dev * 100))

        if outlier_reqs:
            anomalies.append({
                "type": "LENGTH_OUTLIERS",
                "title": "Response Body Length Outliers (>10% deviation from baseline)",
                "severity": "MEDIUM",
                "details": f"{len(outlier_reqs)} requests had response body sizes deviating from baseline ({base_len} bytes).",
                "affected_indices": [idx for idx, _, _ in outlier_reqs]
            })

    # 3. Check for Database Lock Timeouts & Latency Spikes
    if baseline_result and baseline_result.get("duration"):
        base_dur = baseline_result["duration"]
        slow_reqs = [r for r in results if r.get("duration", 0) > (base_dur * 3.0) and r.get("duration", 0) > 0.5]
        if slow_reqs:
            anomalies.append({
                "type": "DB_LOCK_TIMEOUT_SPIKE",
                "title": "Database Lock Contention / High Latency Spikes (>3x baseline)",
                "severity": "HIGH",
                "details": f"{len(slow_reqs)} requests experienced latency spikes (>3x baseline of {base_dur:.4f}s), indicating database row locking.",
                "affected_indices": [r["index"] for r in slow_reqs]
            })

    # 4. Check for Server Error Spikes (HTTP 500 / 504)
    server_errors = [r for r in results if r.get("status_code", 0) >= 500]
    if server_errors:
        anomalies.append({
            "type": "SERVER_ERROR_SPIKE",
            "title": "Server Internal Errors / Lock Timeouts (5xx)",
            "severity": "HIGH",
            "details": f"{len(server_errors)} requests triggered 5xx server errors during the concurrent race burst.",
            "affected_indices": [r["index"] for r in server_errors]
        })

    return anomalies

# HTTP ENGINE & HTTP/2 SINGLE-PACKET ATTACK (LAST-BYTE SYNC)

async def send_req_httpx(
    client: httpx.AsyncClient,
    req_template: Dict[str, Any],
    idx: int,
    start_event: asyncio.Event,
    payload: str,
    session_info: Optional[Dict[str, Any]],
    rate_limit: float,
    isolate_sessions: bool,
    success_codes: List[int],
    success_string: Optional[str],
    save_bodies_dir: Optional[str],
    verbose: bool,
    results: List[Dict[str, Any]],
    pbar: Optional[Any] = None
):
    """Executes standard HTTP/1.1 or standard HTTP/2 request with asyncio.Event synchronization."""
    # Render dynamic template variables
    method = render_template(req_template["method"], idx, payload, session_info).upper()
    url = render_template(req_template["url"], idx, payload, session_info)

    headers = dict(req_template.get("headers", {}))
    # Inject session headers if provided
    if session_info:
        for sk, sv in session_info.items():
            headers[sk] = sv

    headers = {k: str(render_template(v, idx, payload, session_info)) for k, v in headers.items()}
    body = req_template.get("body")
    if body is not None:
        body = render_template(body, idx, payload, session_info)

    kwargs = {
        "method": method,
        "url": url,
        "headers": headers,
        "timeout": req_template.get("timeout", 10.0)
    }

    if body is not None:
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["content"] = str(body)

    if isolate_sessions:
        kwargs["cookies"] = httpx.Cookies()

    # Wait for the barrier release signal
    await start_event.wait()

    if rate_limit > 0:
        delay = (idx - 1) / rate_limit
        await asyncio.sleep(delay)

    start_time = time.perf_counter()
    try:
        resp = await client.request(**kwargs)
        duration = time.perf_counter() - start_time

        status_code = resp.status_code
        reason = resp.reason_phrase or ""
        resp_content = resp.content
        length = len(resp_content)

        is_success = True
        has_criteria = bool(success_codes) or bool(success_string)
        if success_codes and status_code not in success_codes:
            is_success = False
        if success_string:
            try:
                if success_string.lower() not in resp.text.lower():
                    is_success = False
            except Exception:
                is_success = False

        result = {
            "index": idx,
            "status_code": status_code,
            "reason": reason,
            "duration": duration,
            "length": length,
            "error": None,
            "success": is_success if has_criteria else None
        }
        results.append(result)

        if save_bodies_dir:
            try:
                os.makedirs(save_bodies_dir, exist_ok=True)
                filename = f"request_{idx:03d}_{status_code}.txt"
                filepath = os.path.join(save_bodies_dir, filename)
                with open(filepath, "wb") as f:
                    f.write(resp_content)
            except Exception:
                pass

        output_line = f"request {idx:3d} -> {color_status(status_code)} {reason} ({duration:.4f}s)"
        if pbar:
            pbar.write(output_line)
        elif not has_rich:
            print(output_line)

    except Exception as e:
        duration = time.perf_counter() - start_time
        err_description = friendly_network_error(e, req_template.get("timeout", 10.0))
        result = {
            "index": idx,
            "status_code": 0,
            "reason": "ERROR",
            "duration": duration,
            "length": 0,
            "error": err_description,
            "success": False if (success_codes or success_string) else None
        }
        results.append(result)

        err_msg = f"request {idx:3d} -> {Fore.RED}ERROR: {err_description}{Style.RESET_ALL} ({duration:.4f}s)"
        if pbar:
            pbar.write(err_msg)
        elif not has_rich:
            print(err_msg)

async def run_h2_single_packet_sync(
    req_template: Dict[str, Any],
    concurrency: int,
    verify: bool,
    sessions: List[Dict[str, Any]],
    wordlist: List[str],
    results: List[Dict[str, Any]]
) -> float:
    """
    HTTP/2 Single-Packet Attack (Last-Byte Synchronization):
    Opens an HTTP/2 TLS connection using `h2`.
    Pre-sends headers and all payload bytes EXCEPT the final byte across all N streams.
    Pauses until all streams are staged, then transmits all remaining bytes in a single TCP write flush.
    Achieves microsecond-level concurrent arrival at the target.
    """
    parsed_url = urllib.parse.urlparse(req_template["url"])
    host = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    path = parsed_url.path or "/"
    if parsed_url.query:
        path += "?" + parsed_url.query

    # Configure TLS context for HTTP/2 ALPN
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    reader, writer = await asyncio.open_connection(host, port, ssl=(parsed_url.scheme == "https"), ssl_handshake_timeout=10.0)

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()

    # Pre-stage requests across streams
    streams = {}
    staged_frames = []

    for idx in range(1, concurrency + 1):
        payload = wordlist[(idx - 1) % len(wordlist)] if wordlist else ""
        session_info = sessions[(idx - 1) % len(sessions)] if sessions else None

        req_method = render_template(req_template["method"], idx, payload, session_info).upper()
        req_url = render_template(path, idx, payload, session_info)

        headers = [
            (":method", req_method),
            (":authority", host),
            (":scheme", parsed_url.scheme),
            (":path", req_url),
            ("user-agent", "NFR-Race/1.0 (Single-Packet Attack)")
        ]

        raw_headers = dict(req_template.get("headers", {}))
        if session_info:
            for sk, sv in session_info.items():
                raw_headers[sk] = sv
        for hk, hv in raw_headers.items():
            if hk.lower() not in ("host", "user-agent", "content-length"):
                headers.append((hk.lower(), str(render_template(hv, idx, payload, session_info))))

        body = req_template.get("body")
        body_bytes = b""
        if body is not None:
            rendered_body = render_template(body, idx, payload, session_info)
            if isinstance(rendered_body, (dict, list)):
                body_bytes = json.dumps(rendered_body).encode("utf-8")
                headers.append(("content-type", "application/json"))
            else:
                body_bytes = str(rendered_body).encode("utf-8")

        headers.append(("content-length", str(len(body_bytes))))

        stream_id = conn.get_next_available_stream_id()
        has_body = len(body_bytes) > 0

        # Send headers frame (end_stream=False if body present)
        conn.send_headers(stream_id, headers, end_stream=not has_body)

        last_byte = b""
        if has_body:
            if len(body_bytes) > 1:
                # Send body except last 1 byte
                conn.send_data(stream_id, body_bytes[:-1], end_stream=False)
                last_byte = body_bytes[-1:]
            else:
                last_byte = body_bytes

        streams[stream_id] = {
            "index": idx,
            "last_byte": last_byte,
            "has_body": has_body,
            "status": 0,
            "length": 0,
            "data": b""
        }

    # Flush pre-staged frames to transport buffer
    writer.write(conn.data_to_send())
    await writer.drain()

    # Pause 50ms to ensure TCP socket buffers settle before release
    await asyncio.sleep(0.05)

    # 🚀 SINGLE-PACKET RELEASE BARRIER
    race_start_time = time.perf_counter()

    for stream_id, s_info in streams.items():
        if s_info["has_body"]:
            conn.send_data(stream_id, s_info["last_byte"], end_stream=True)

    # Write all final stream bytes in a SINGLE TCP write packet!
    writer.write(conn.data_to_send())
    sock = writer.get_extra_info("socket")
    if sock:
        try:
            sock.setsockopt(ssl.IPPROTO_TCP if hasattr(ssl, 'IPPROTO_TCP') else 6, 1, 1)  # TCP_NODELAY force flush
        except Exception:
            pass
    await writer.drain()

    # Read responses from host
    response_counter = 0
    timeout_deadline = time.perf_counter() + req_template.get("timeout", 10.0)

    while response_counter < len(streams) and time.perf_counter() < timeout_deadline:
        try:
            raw_data = await asyncio.wait_for(reader.read(65536), timeout=0.5)
            if not raw_data:
                break
            events = conn.receive_data(raw_data)
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    s_id = event.stream_id
                    if s_id in streams:
                        for hk, hv in event.headers:
                            if hk == b":status":
                                streams[s_id]["status"] = int(hv.decode())
                elif isinstance(event, h2.events.DataReceived):
                    s_id = event.stream_id
                    if s_id in streams:
                        streams[s_id]["data"] += event.data
                elif isinstance(event, h2.events.StreamEnded):
                    s_id = event.stream_id
                    if s_id in streams:
                        streams[s_id]["length"] = len(streams[s_id]["data"])
                        response_counter += 1
        except asyncio.TimeoutError:
            continue
        except Exception:
            break

    total_time = time.perf_counter() - race_start_time
    writer.close()

    for s_id, s_info in streams.items():
        results.append({
            "index": s_info["index"],
            "status_code": s_info["status"],
            "reason": "OK" if s_info["status"] == 200 else "",
            "duration": total_time,
            "length": s_info["length"],
            "error": "Timeout or Stream Closed" if s_info["status"] == 0 else None,
            "success": (200 <= s_info["status"] < 300) if s_info["status"] > 0 else False
        })

    return total_time

async def run_warmup(
    client: httpx.AsyncClient,
    req_template: Dict[str, Any],
    count: int,
    warmup_delay: float
):
    """Executes pre-flight warm-up requests to pre-establish TCP & TLS handshakes."""
    print(f"{Fore.YELLOW}Performing {count} warm-up request(s) to establish connections...{Style.RESET_ALL}")
    for i in range(count):
        idx = -(i + 1)
        method = render_template(req_template["method"], idx).upper()
        url = render_template(req_template["url"], idx)
        headers = {k: str(render_template(v, idx)) for k, v in req_template.get("headers", {}).items()}
        kwargs = {"method": method, "url": url, "headers": headers, "timeout": req_template.get("timeout", 10.0)}

        try:
            start_time = time.perf_counter()
            resp = await client.request(**kwargs)
            duration = time.perf_counter() - start_time
            print(f"  Warm-up {i+1}/{count} -> {color_status(resp.status_code)} {resp.reason_phrase or ''} ({duration:.4f}s)")
        except Exception as e:
            err_desc = friendly_network_error(e, req_template.get("timeout", 10.0))
            print(f"  Warm-up {i+1}/{count} -> {Fore.RED}ERROR: {err_desc}{Style.RESET_ALL}")

        if warmup_delay > 0 and i < count - 1:
            await asyncio.sleep(warmup_delay)
    print(f"{Fore.GREEN}Warm-up completed.{Style.RESET_ALL}\n")

# REPORT EXPORTERS (JSON, HTML & SARIF)

def export_results_json(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int,
    output_path: str,
    anomalies: List[Dict[str, Any]]
):
    total = len(results)
    success_count = sum(1 for r in results if r["status_code"] > 0 and r["error"] is None)
    fail_count = total - success_count
    durations = [r["duration"] for r in results if r["error"] is None]

    status_counts = {}
    for r in results:
        code = str(r["status_code"]) if r["status_code"] > 0 else "ERROR"
        status_counts[code] = status_counts.get(code, 0) + 1

    stats = calculate_percentiles(durations) if durations else {}

    output_data = {
        "summary": {
            "total_requests": total,
            "concurrency": concurrency,
            "successful_requests": success_count,
            "failed_requests": fail_count,
            "total_time_sec": total_time,
            "requests_per_second": total / total_time if total_time > 0 else 0,
            "statistics": stats,
            "status_code_breakdown": status_counts,
            "anomalies_detected": anomalies
        },
        "requests": results
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4)
        print(f"{Fore.GREEN}JSON Results successfully exported to {output_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to export JSON results to {output_path}: {e}{Style.RESET_ALL}\n")

def export_sarif_report(
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
    anomalies: List[Dict[str, Any]],
    sarif_path: str
):
    """
    Exports a SARIF v2.1.0 report formatted specifically for HackerOne, Bugcrowd,
    DefectDojo, and GitHub Security vulnerability management platforms.
    """
    sarif_results = []
    for idx, anomaly in enumerate(anomalies):
        sarif_results.append({
            "ruleId": f"NFR-RACE-00{idx+1}",
            "level": "error" if anomaly["severity"] == "HIGH" else "warning",
            "message": {
                "text": f"{anomaly['title']}: {anomaly['details']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": config.get("url", "https://target.local")
                        }
                    }
                }
            ],
            "properties": {
                "affectedRequestIndices": anomaly.get("affected_indices", []),
                "targetMethod": config.get("method", "POST")
            }
        })

    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NFR Need For Race Engine",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Asbawy/NFR",
                        "rules": [
                            {
                                "id": "NFR-RACE-001",
                                "name": "HTTP Race Condition Vulnerability",
                                "shortDescription": {
                                    "text": "Concurrent HTTP request processing vulnerability / race condition."
                                },
                                "fullDescription": {
                                    "text": "Target server accepts concurrent duplicate actions without sufficient synchronization or database isolation."
                                },
                                "defaultConfiguration": {
                                    "level": "error"
                                }
                            }
                        ]
                    }
                },
                "results": sarif_results
            }
        ]
    }

    try:
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=4)
        print(f"{Fore.GREEN}SARIF Report successfully exported to {sarif_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to export SARIF report to {sarif_path}: {e}{Style.RESET_ALL}\n")

def generate_html_report(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int,
    config: Dict[str, Any],
    anomalies: List[Dict[str, Any]],
    html_path: str
):
    import html
    total = len(results)
    success_count = sum(1 for r in results if r["status_code"] > 0 and r["error"] is None)
    fail_count = total - success_count
    durations = [r["duration"] for r in results if r["error"] is None]
    stats = calculate_percentiles(durations) if durations else {}

    reqs_json = json.dumps(results)
    anomalies_json = json.dumps(anomalies)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NFR Race Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #151d30;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --success: #10b981;
            --error: #ef4444;
            --warning: #f59e0b;
            --border: #1f2937;
        }}
        body {{ background-color: var(--bg-color); color: var(--text-color); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; background-color: rgba(59, 130, 246, 0.2); color: var(--primary); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }}
        .card {{ background-color: var(--card-bg); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; }}
        .card-title {{ font-size: 0.875rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }}
        .card-value {{ font-size: 1.75rem; font-weight: 700; }}
        .card-value.success {{ color: var(--success); }}
        .card-value.error {{ color: var(--error); }}
        .anomaly-card {{ background-color: rgba(239, 68, 68, 0.1); border: 1px solid var(--error); padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: rgba(255, 255, 255, 0.03); color: var(--text-muted); }}
        .status-2xx {{ color: var(--success); }}
        .status-err {{ color: var(--error); }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>NFR Race Security Audit Report</h1>
                <p style="color: var(--text-muted);">Target: <code style="color: var(--primary);">{html.escape(config.get('url', ''))}</code></p>
            </div>
            <span class="badge">{config.get('method', 'POST').upper()}</span>
        </header>

        <div class="grid">
            <div class="card"><div class="card-title">Total Requests</div><div class="card-value">{total}</div></div>
            <div class="card"><div class="card-title">Successful (2xx)</div><div class="card-value success">{success_count}</div></div>
            <div class="card"><div class="card-title">Failed / Errors</div><div class="card-value error">{fail_count}</div></div>
            <div class="card"><div class="card-title">Total Time</div><div class="card-value">{total_time:.4f}s</div></div>
            <div class="card"><div class="card-title">Throughput</div><div class="card-value" style="color: var(--primary);">{total / total_time if total_time > 0 else 0:.2f} RPS</div></div>
        </div>

        {"<h2 style='color: var(--error);'>🚨 Identified Anomalies & Vulnerabilities</h2>" if anomalies else ""}
        {"".join(f"<div class='anomaly-card'><strong>[{a['severity']}] {html.escape(a['title'])}</strong><p>{html.escape(a['details'])}</p><p><small>Affected Requests: {a.get('affected_indices', [])}</small></p></div>" for a in anomalies)}

        <div class="card" style="margin-top: 2rem;">
            <h2>Response Latency Distribution</h2>
            <table>
                <tr><th>Metric</th><th>Latency (seconds)</th></tr>
                <tr><td>Min</td><td>{stats.get('min', 0):.4f}s</td></tr>
                <tr><td>p50 (Median)</td><td>{stats.get('p50', 0):.4f}s</td></tr>
                <tr><td>Average</td><td>{stats.get('avg', 0):.4f}s</td></tr>
                <tr><td>p90</td><td>{stats.get('p90', 0):.4f}s</td></tr>
                <tr><td>p95</td><td>{stats.get('p95', 0):.4f}s</td></tr>
                <tr><td>p99</td><td>{stats.get('p99', 0):.4f}s</td></tr>
                <tr><td>Max</td><td>{stats.get('max', 0):.4f}s</td></tr>
            </table>
        </div>
    </div>
</body>
</html>
"""
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{Fore.GREEN}HTML Report successfully written to {html_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to write HTML Report: {e}{Style.RESET_ALL}\n")

# MAIN WORKFLOW & CLI INTERFACE

async def race(
    req_template: Dict[str, Any],
    concurrency: int,
    timeout: float,
    verify: bool,
    http2: bool,
    http2_sync: bool,
    warmup_count: int,
    warmup_delay: float,
    rate_limit: float,
    isolate_sessions: bool,
    success_codes: List[int],
    success_string: Optional[str],
    save_bodies_dir: Optional[str],
    verbose: bool,
    proxy: Optional[str],
    output_path: Optional[str],
    html_path: Optional[str],
    sarif_path: Optional[str],
    wordlist: List[str],
    sessions: List[Dict[str, Any]],
    baseline: bool
):
    results = []
    baseline_result = None

    # Step 1: Baseline Request Execution
    if baseline:
        print(f"{Fore.CYAN}Executing Baseline Request (N = 1) to measure target response signature...{Style.RESET_ALL}")
        limits = httpx.Limits(max_connections=5)
        client_kwargs = {"http2": http2, "verify": verify, "limits": limits}
        if proxy:
            client_kwargs["proxy"] = proxy

        async with httpx.AsyncClient(**client_kwargs) as baseline_client:
            b_start = asyncio.Event()
            b_start.set()
            b_results = []
            await send_req_httpx(
                client=baseline_client,
                req_template=req_template,
                idx=0,
                start_event=b_start,
                payload=wordlist[0] if wordlist else "",
                session_info=sessions[0] if sessions else None,
                rate_limit=0,
                isolate_sessions=isolate_sessions,
                success_codes=success_codes,
                success_string=success_string,
                save_bodies_dir=None,
                verbose=False,
                results=b_results
            )
            if b_results:
                baseline_result = b_results[0]
                b_code = baseline_result.get("status_code", 0)
                b_dur = baseline_result.get("duration", 0.0)
                b_len = baseline_result.get("length", 0)
                print(f"  Baseline Signature -> Status: {color_status(b_code)} | Size: {b_len} bytes | Latency: {b_dur:.4f}s\n")

    # Step 2: Connection Warm-up
    if warmup_count > 0 and not http2_sync:
        limits = httpx.Limits(max_connections=concurrency + 10)
        client_kwargs = {"http2": http2, "verify": verify, "limits": limits}
        if proxy:
            client_kwargs["proxy"] = proxy
        async with httpx.AsyncClient(**client_kwargs) as warmup_client:
            await run_warmup(warmup_client, req_template, warmup_count, warmup_delay)

    # Step 3: Race Execution
    total_time = 0.0
    if http2_sync:
        if not has_h2:
            print_startup_error(
                stage="ENGINE SETUP",
                title="Missing HTTP/2 Dependency",
                details="HTTP/2 Single-Packet Attack requires the 'h2' library.",
                hint="Install dependencies via: pip install h2 rich"
            )
            sys.exit(1)
        print(f"{Fore.MAGENTA}{Style.BRIGHT}⚡ Launching HTTP/2 Last-Byte Synchronization (Single-Packet Attack) for {concurrency} streams...{Style.RESET_ALL}")
        total_time = await run_h2_single_packet_sync(
            req_template=req_template,
            concurrency=concurrency,
            verify=verify,
            sessions=sessions,
            wordlist=wordlist,
            results=results
        )
    else:
        limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency + 10)
        client_kwargs = {"http2": http2, "verify": verify, "limits": limits}
        if proxy:
            client_kwargs["proxy"] = proxy

        async with httpx.AsyncClient(**client_kwargs) as client:
            start_event = asyncio.Event()
            pbar = tqdm(total=concurrency, desc="Racing requests") if has_tqdm and not has_rich else None

            tasks = []
            for i in range(concurrency):
                payload = wordlist[i % len(wordlist)] if wordlist else ""
                session_info = sessions[i % len(sessions)] if sessions else None

                tasks.append(send_req_httpx(
                    client=client,
                    req_template=req_template,
                    idx=i + 1,
                    start_event=start_event,
                    payload=payload,
                    session_info=session_info,
                    rate_limit=rate_limit,
                    isolate_sessions=isolate_sessions,
                    success_codes=success_codes,
                    success_string=success_string,
                    save_bodies_dir=save_bodies_dir,
                    verbose=verbose,
                    results=results,
                    pbar=pbar
                ))

            print(f"{Fore.CYAN}Ready... Set... Go! Releasing barrier for {concurrency} concurrent requests...{Style.RESET_ALL}")
            race_start_time = time.perf_counter()
            start_event.set()
            await asyncio.gather(*tasks)
            total_time = time.perf_counter() - race_start_time

            if pbar:
                pbar.close()

    # Step 4: Differential Anomaly Analysis
    anomalies = analyze_differential_anomalies(results, baseline_result)

    # Step 5: Summary Output & Reports
    print_summary_console(results, total_time, concurrency, anomalies)

    if output_path:
        export_results_json(results, total_time, concurrency, output_path, anomalies)
    if html_path:
        generate_html_report(results, total_time, concurrency, req_template, anomalies, html_path)
    if sarif_path:
        export_sarif_report(results, req_template, anomalies, sarif_path)

def print_summary_console(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int,
    anomalies: List[Dict[str, Any]]
):
    total = len(results)
    if total == 0:
        print(f"{Fore.RED}No results recorded.{Style.RESET_ALL}")
        return

    success_count = sum(1 for r in results if r["status_code"] > 0 and r["error"] is None)
    fail_count = total - success_count
    durations = [r["duration"] for r in results if r["error"] is None]
    stats = calculate_percentiles(durations) if durations else {}
    rps = total / total_time if total_time > 0 else 0

    print("=" * 60)
    print(f"{Fore.CYAN}{Style.BRIGHT}{'RACE RESULTS SUMMARY':^60}{Style.RESET_ALL}")
    print("=" * 60)
    print(f"Total Requests:     {total}")
    print(f"Concurrency:        {concurrency}")
    print(f"Successful:         {Fore.GREEN}{success_count}{Style.RESET_ALL}")
    print(f"Failed:             {Fore.RED if fail_count > 0 else Fore.GREEN}{fail_count}{Style.RESET_ALL}")
    print(f"Total Race Time:    {total_time:.4f}s")
    print(f"Requests/Second:    {rps:.2f} RPS")

    if stats:
        print("-" * 60)
        print(f"{Fore.YELLOW}{'Response Time Statistics':^60}{Style.RESET_ALL}")
        print("-" * 60)
        print(f"Min: {stats['min']:.4f}s | p50: {stats['p50']:.4f}s | p90: {stats['p90']:.4f}s | Max: {stats['max']:.4f}s")

    if anomalies:
        print("-" * 60)
        print(f"{Fore.RED}{Style.BRIGHT}{'⚠️ DETECTED ANOMALIES & RACE VULNERABILITIES':^60}{Style.RESET_ALL}")
        print("-" * 60)
        for a in anomalies:
            print(f"• [{Fore.RED}{a['severity']}{Style.RESET_ALL}] {Fore.YELLOW}{a['title']}{Style.RESET_ALL}")
            print(f"  Details: {a['details']}")
            print(f"  Affected Request Indices: {a.get('affected_indices', [])}")
            print()

    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="NFR - NEED FOR RACE (Master HTTP Race Condition Framework)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-y", "--yaml", help="Path to YAML configuration file")
    group.add_argument("-r", "--raw", help="Path to raw HTTP request file (Burp Suite format)")

    parser.add_argument("--raw-http", action="store_true", help="Force HTTP protocol instead of HTTPS when parsing raw request")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrency level (default: 10)")
    parser.add_argument("-t", "--timeout", type=float, help="Request timeout in seconds (default: 10.0)")
    parser.add_argument("--verify", action="store_true", default=None, help="Enable SSL certification verification")
    parser.add_argument("--no-verify", action="store_false", dest="verify", help="Disable SSL certification verification (default)")
    parser.add_argument("--http2", action="store_true", default=None, help="Enable standard HTTP/2 support")
    parser.add_argument("--http2-sync", "--h2-sync", action="store_true", help="Enable HTTP/2 Last-Byte Synchronization (Single-Packet Attack)")
    parser.add_argument("-w", "--warmup", type=int, help="Number of warm-up requests to execute (default: 3)")
    parser.add_argument("--no-warmup", action="store_const", const=0, dest="warmup", help="Disable warm-up requests")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full response headers and bodies")
    parser.add_argument("-o", "--output", help="Path to export JSON results file")
    parser.add_argument("--html", help="Path to write interactive HTML report")
    parser.add_argument("--sarif", help="Path to export SARIF v2.1.0 report for Bug Bounty / Security scanners")
    parser.add_argument("--proxy", help="Upstream HTTP/Socks proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--wordlist", help="Path to payload wordlist file to substitute {{payload}}")
    parser.add_argument("--sessions", help="Path to session pool file (.txt, .json, or .yaml) for multi-account testing")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Pace request releases to a maximum rate (RPS)")
    parser.add_argument("--warmup-delay", type=float, default=0.0, help="Delay in seconds between sequential warmup requests")
    parser.add_argument("--isolate-sessions", action="store_true", help="Isolate session states per request")
    parser.add_argument("--baseline", action="store_true", default=True, help="Execute baseline request (N=1) for differential anomaly detection (default)")
    parser.add_argument("--no-baseline", action="store_false", dest="baseline", help="Disable baseline request")
    parser.add_argument("--success-code", help="Comma-separated status codes to determine success (e.g. 200,201)")
    parser.add_argument("--success-string", help="Body substring to search for to determine success")
    parser.add_argument("--save-bodies", help="Directory path to save full response bodies")

    args = parser.parse_args()

    # Load configuration
    if args.yaml:
        try:
            req = load_yaml(args.yaml)
        except Exception as e:
            print_startup_error(stage="CONFIG LOAD", title="YAML Load Failed", details=str(e))
            sys.exit(1)
    elif args.raw:
        try:
            req = parse_raw_request(args.raw, force_http=args.raw_http)
        except Exception as e:
            print_startup_error(stage="RAW REQUEST PARSE", title="Raw Request Parse Failed", details=str(e))
            sys.exit(1)

    wordlist = load_wordlist(args.wordlist) if args.wordlist else []
    sessions = load_sessions(args.sessions) if args.sessions else []

    success_codes = []
    if args.success_code:
        try:
            success_codes = [int(x.strip()) for x in args.success_code.split(",")]
        except Exception:
            pass

    concurrency = args.concurrency if args.concurrency is not None else req.get("concurrency", 10)
    timeout = args.timeout if args.timeout is not None else req.get("timeout", 10.0)
    verify = args.verify if args.verify is not None else req.get("verify", False)
    http2 = args.http2 if args.http2 is not None else req.get("http2", False)
    warmup_count = args.warmup if args.warmup is not None else req.get("warmup", 3)
    req["timeout"] = timeout

    print(f"{Fore.CYAN}{Style.BRIGHT}🏎️ NFR Engine Configuration:{Style.RESET_ALL}")
    print(f"  Target URL:       {req['url']}")
    print(f"  Method:           {req['method']}")
    print(f"  Concurrency:      {concurrency}")
    print(f"  HTTP/2 Sync:      {args.http2_sync}")
    print(f"  Sessions Pool:    {len(sessions)} session(s)")
    print(f"  Wordlist:         {len(wordlist)} item(s)")
    print(f"  Baseline Engine:  {args.baseline}")
    print()

    asyncio.run(race(
        req_template=req,
        concurrency=concurrency,
        timeout=timeout,
        verify=verify,
        http2=http2,
        http2_sync=args.http2_sync,
        warmup_count=warmup_count,
        warmup_delay=args.warmup_delay,
        rate_limit=args.rate_limit,
        isolate_sessions=args.isolate_sessions,
        success_codes=success_codes,
        success_string=args.success_string,
        save_bodies_dir=args.save_bodies,
        verbose=args.verbose,
        proxy=args.proxy,
        output_path=args.output,
        html_path=args.html,
        sarif_path=args.sarif,
        wordlist=wordlist,
        sessions=sessions,
        baseline=args.baseline
    ))

if __name__ == "__main__":
    main()