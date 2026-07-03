#!/usr/bin/env python3

# Usage: python3 NFR.py --raw request.txt --concurrency 20

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
import urllib.parse
from typing import Dict, Any, List, Optional
import yaml
import httpx
from colorama import init, Fore, Style

# Try to import tqdm for progress bar
try:
    from tqdm import tqdm
    has_tqdm = True
except ImportError:
    has_tqdm = False

init(autoreset=True)

def color_status(status_code: int) -> str:
    if 200 <= status_code < 300:
        return f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
    elif 300 <= status_code < 400:
        return f"{Fore.YELLOW}{status_code}{Style.RESET_ALL}"
    elif 400 <= status_code < 500:
        return f"{Fore.RED}{status_code}{Style.RESET_ALL}"
    else:
        return f"{Fore.MAGENTA}{status_code}{Style.RESET_ALL}"

def print_startup_error(stage: str, title: str, details: str, hint: Optional[str] = None):
    """Prints a beautiful, highly visible error card in the console."""
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
    """Translates generic httpx exceptions into friendly user-readable explanations."""
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

def render_template(val: Any, idx: int, payload: str = "") -> Any:
    """Recursively replaces template placeholders in configuration values."""
    if isinstance(val, str):
        res = val
        
        # 1. Replace wordlist payload
        if "{{payload}}" in res:
            res = res.replace("{{payload}}", payload)
            
        # 2. Replace random_int
        if "{{random_int}}" in res:
            while "{{random_int}}" in res:
                res = res.replace("{{random_int}}", str(random.randint(100000, 999999)), 1)
                
        # 3. Replace timestamp
        if "{{timestamp}}" in res:
            while "{{timestamp}}" in res:
                res = res.replace("{{timestamp}}", str(int(time.time() * 1000)), 1)
                
        # 4. Replace uuid
        if "{{uuid}}" in res:
            while "{{uuid}}" in res:
                res = res.replace("{{uuid}}", str(uuid.uuid4()), 1)
                
        # 5. Replace index / sequence
        if "{{index}}" in res:
            res = res.replace("{{index}}", str(idx))
        if "{{seq}}" in res:
            res = res.replace("{{seq}}", str(idx))
            
        # 6. Replace random_str:N
        if "{{random_str:" in res:
            matches = re.findall(r"\{\{random_str:(\d+)\}\}", res)
            for m in matches:
                length = int(m)
                rand_s = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))
                res = res.replace(f"{{{{random_str:{m}}}}}", rand_s, 1)
                
        # 7. URL encoding wrapper: {{urlencode(...)}}
        # This will evaluate inside out. Since we replace values above first,
        # any inner tag (like {{uuid}}) will already be evaluated.
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
        return {k: render_template(v, idx, payload) for k, v in val.items()}
    elif isinstance(val, list):
        return [render_template(v, idx, payload) for v in val]
    return val

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

def parse_raw_request(file_path: str, force_http: bool = False) -> Dict[str, Any]:
    """Parses a raw HTTP request (e.g. from Burp Suite) into a configuration dictionary."""
    with open(file_path, "rb") as f:
        content_bytes = f.read()
    
    double_crlf = b"\r\n\r\n"
    double_lf = b"\n\n"
    
    header_part = b""
    body_bytes = b""
    
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

async def send_req(
    client: httpx.AsyncClient,
    req_template: Dict[str, Any],
    idx: int,
    start_event: asyncio.Event,
    payload: str,
    rate_limit: float,
    isolate_sessions: bool,
    success_codes: List[int],
    success_string: Optional[str],
    save_bodies_dir: Optional[str],
    verbose: bool,
    results: List[Dict[str, Any]],
    pbar: Optional[Any] = None
):
    # Render variables dynamically for this specific request index & payload
    method = render_template(req_template["method"], idx, payload).upper()
    url = render_template(req_template["url"], idx, payload)
    headers = req_template.get("headers", {})
    headers = {k: str(render_template(v, idx, payload)) for k, v in headers.items()}
    body = req_template.get("body")
    if body is not None:
        body = render_template(body, idx, payload)
    
    kwargs = {
        "method": method,
        "url": url,
        "headers": headers,
        "timeout": req_template.get("timeout", 10.0)
    }
    
    if body:
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["content"] = body

    if isolate_sessions:
        # Pass isolated empty cookie container to request
        kwargs["cookies"] = httpx.Cookies()

    # Wait for the synchronization barrier before starting the request
    await start_event.wait()
    
    # If rate limit (RPS) is configured, delay task release
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
        
        # Check Success Criteria
        is_success = True
        has_criteria = bool(success_codes) or bool(success_string)
        if success_codes and status_code not in success_codes:
            is_success = False
        if success_string:
            try:
                resp_text = resp.text
                if success_string.lower() not in resp_text.lower():
                    is_success = False
            except Exception:
                is_success = False
                
        # Log result
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
        
        # Save body if directory configured
        if save_bodies_dir:
            try:
                os.makedirs(save_bodies_dir, exist_ok=True)
                filename = f"request_{idx:03d}_{status_code}.txt"
                filepath = os.path.join(save_bodies_dir, filename)
                with open(filepath, "wb") as f:
                    f.write(resp_content)
            except Exception as e:
                pass
        
        status_colored = color_status(status_code)
        success_tag = ""
        if has_criteria:
            if is_success:
                success_tag = f" {Fore.GREEN}[SUCCESS]{Style.RESET_ALL}"
            else:
                success_tag = f" {Fore.RED}[FAILED]{Style.RESET_ALL}"
                
        output_line = f"request {idx:3d} -> {status_colored} {reason} ({duration:.4f}s){success_tag}"
        
        if pbar:
            pbar.write(output_line)
        else:
            print(output_line)
            
        if verbose:
            verbose_output = [
                f"  [Request {idx}] URL: {url}",
                f"  [Request {idx}] Headers: {headers}",
            ]
            if body:
                verbose_output.append(f"  [Request {idx}] Body: {body}")
            verbose_output.append(f"  [Response {idx}] Status: {status_code}")
            verbose_output.append(f"  [Response {idx}] Headers: {dict(resp.headers)}")
            try:
                resp_text = resp.text
                if len(resp_text) > 500:
                    resp_text = resp_text[:500] + "..."
                verbose_output.append(f"  [Response {idx}] Body: {resp_text}")
            except Exception:
                verbose_output.append(f"  [Response {idx}] Body: <binary or unreadable>")
            
            verbose_text = "\n".join(verbose_output)
            if pbar:
                pbar.write(verbose_text)
            else:
                print(verbose_text)
                
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
        else:
            print(err_msg)
    finally:
        if pbar:
            pbar.update(1)

async def run_warmup(
    client: httpx.AsyncClient,
    req_template: Dict[str, Any],
    count: int,
    warmup_delay: float
):
    print(f"{Fore.YELLOW}Performing {count} warm-up request(s) to establish connections...{Style.RESET_ALL}")
    
    for i in range(count):
        idx = -(i + 1)
        method = render_template(req_template["method"], idx).upper()
        url = render_template(req_template["url"], idx)
        headers = req_template.get("headers", {})
        headers = {k: str(render_template(v, idx)) for k, v in headers.items()}
        body = req_template.get("body")
        if body is not None:
            body = render_template(body, idx)
        
        kwargs = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": req_template.get("timeout", 10.0)
        }
        if body:
            if isinstance(body, (dict, list)):
                kwargs["json"] = body
            else:
                kwargs["content"] = body
                
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

def print_summary(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int
):
    total = len(results)
    if total == 0:
        print(f"{Fore.RED}No results recorded.{Style.RESET_ALL}")
        return

    success_count = sum(1 for r in results if r["status_code"] > 0 and r["error"] is None)
    fail_count = total - success_count
    durations = [r["duration"] for r in results if r["error"] is None]
    
    status_counts = {}
    for r in results:
        code = str(r["status_code"]) if r["status_code"] > 0 else "ERROR"
        reason = r["reason"]
        key = f"{code} {reason}".strip()
        status_counts[key] = status_counts.get(key, 0) + 1
        
    rps = total / total_time if total_time > 0 else 0

    print("=" * 60)
    print(f"{Fore.CYAN}{'RACE RESULTS SUMMARY':^60}{Style.RESET_ALL}")
    print("=" * 60)
    print(f"Total Requests:     {total}")
    print(f"Concurrency:        {concurrency}")
    print(f"Successful:         {Fore.GREEN}{success_count}{Style.RESET_ALL}")
    print(f"Failed:             {Fore.RED if fail_count > 0 else Fore.GREEN}{fail_count}{Style.RESET_ALL}")
    print(f"Total Race Time:    {total_time:.4f}s")
    print(f"Requests/Second:    {rps:.2f} RPS")
    print("-" * 60)
    
    if durations:
        stats = calculate_percentiles(durations)
        print(f"{Fore.YELLOW}{'Response Time Statistics (Successful Requests)':^60}{Style.RESET_ALL}")
        print("-" * 60)
        print(f"Min:                {stats['min']:.4f}s")
        print(f"Max:                {stats['max']:.4f}s")
        print(f"Average:            {stats['avg']:.4f}s")
        print(f"p50 (Median):       {stats['p50']:.4f}s")
        print(f"p90:                {stats['p90']:.4f}s")
        print(f"p95:                {stats['p95']:.4f}s")
        print(f"p99:                {stats['p99']:.4f}s")
    else:
        print(f"{Fore.RED}{'No successful request duration stats available.':^60}{Style.RESET_ALL}")
        
    print("-" * 60)
    print(f"{Fore.YELLOW}{'Status Code Breakdown':^60}{Style.RESET_ALL}")
    print("-" * 60)
    for status, count in sorted(status_counts.items()):
        colored_status = status
        parts = status.split(" ", 1)
        if parts[0].isdigit():
            colored_status = f"{color_status(int(parts[0]))} {parts[1] if len(parts) > 1 else ''}"
        else:
            colored_status = f"{Fore.RED}{status}{Style.RESET_ALL}"
            
        print(f"{colored_status:<40} : {count}")
        
    # Anomaly/Outlier detection grouping
    groups = {}
    for r in results:
        if r["error"]:
            key = ("ERROR", r["error"])
        else:
            key = (r["status_code"], r["length"])
        groups[key] = groups.get(key, [])
        groups[key].append(r)
        
    outliers = []
    for key, items in groups.items():
        pct = (len(items) / total) * 100
        if pct < 10.0:  # If less than 10% of total requests returned this response
            outliers.append((key, items, pct))
            
    if outliers:
        print("-" * 60)
        print(f"{Fore.MAGENTA}{Style.BRIGHT}{'⚠️ DETECTED ANOMALIES / OUTLIERS (<10% ratio)':^60}{Style.RESET_ALL}")
        print("-" * 60)
        for key, items, percentage in outliers:
            if key[0] == "ERROR":
                print(f"Group: {Fore.RED}ERROR ({key[1]}){Style.RESET_ALL}")
            else:
                status_colored = color_status(key[0])
                print(f"Group: Status {status_colored} | Length: {key[1]} bytes")
            print(f"  Count: {len(items)} requests ({percentage:.2f}%)")
            indices = [str(r["index"]) for r in items]
            print(f"  Request Indices: {', '.join(indices[:15])}{'...' if len(indices) > 15 else ''}")
            
    print("=" * 60)

def generate_html_report(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int,
    config: Dict[str, Any],
    html_path: str
):
    import html
    total = len(results)
    success_count = sum(1 for r in results if r["status_code"] > 0 and r["error"] is None)
    fail_count = total - success_count
    durations = [r["duration"] for r in results if r["error"] is None]
    stats = calculate_percentiles(durations) if durations else {}
    
    # Anomaly grouping
    groups = {}
    for r in results:
        if r["error"]:
            key = ("ERROR", r["error"])
        else:
            key = (r["status_code"], r["length"])
        groups[key] = groups.get(key, 0) + 1
        
    outliers = []
    for key, count in groups.items():
        pct = (count / total) * 100
        if pct < 10.0:
            outliers.append({
                "type": "Error" if key[0] == "ERROR" else "HTTP Response",
                "status": str(key[0]),
                "length": str(key[1]) if key[0] != "ERROR" else "N/A",
                "count": count,
                "percentage": f"{pct:.2f}%"
            })
            
    reqs_json = json.dumps(results)
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NFR Race Results Report</title>
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
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1, h2, h3 {{
            margin: 0;
        }}
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        .badge-primary {{ background-color: rgba(59, 130, 246, 0.2); color: var(--primary); }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        .card-title {{
            font-size: 0.875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        .card-value {{
            font-size: 1.75rem;
            font-weight: 700;
        }}
        .card-value.success {{ color: var(--success); }}
        .card-value.error {{ color: var(--error); }}
        .layout-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2.5rem;
        }}
        @media (max-width: 768px) {{
            .layout-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: rgba(255, 255, 255, 0.03);
            color: var(--text-muted);
            font-weight: 600;
        }}
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.01);
        }}
        .status-2xx {{ color: var(--success); }}
        .status-3xx {{ color: var(--warning); }}
        .status-4xx, .status-5xx, .status-err {{ color: var(--error); }}
        .chart-container {{
            position: relative;
            height: 250px;
            width: 100%;
        }}
        .search-bar {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .search-bar input {{
            flex: 1;
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            color: var(--text-color);
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
        }}
        .scrollable {{
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: 0.25rem;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>NFR Race Results</h1>
                <p style="color: var(--text-muted); margin: 0.25rem 0 0 0;">Target URL: <code style="color: var(--primary);">{html.escape(config.get('url', ''))}</code></p>
            </div>
            <span class="badge badge-primary">Method: {config.get('method', '').upper()}</span>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-title">Total Requests</div>
                <div class="card-value">{total}</div>
            </div>
            <div class="card">
                <div class="card-title">Successful</div>
                <div class="card-value success">{success_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Failed</div>
                <div class="card-value error">{fail_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Total Duration</div>
                <div class="card-value">{total_time:.3f}s</div>
            </div>
            <div class="card">
                <div class="card-title">Throughput</div>
                <div class="card-value" style="color: var(--primary);">{total / total_time if total_time > 0 else 0:.2f} RPS</div>
            </div>
        </div>

        <div class="layout-grid">
            <div class="card">
                <h2>Latency Percentiles</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Metric</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Min Latency</td><td>{stats.get('min', 0):.4f}s</td></tr>
                        <tr><td>p50 (Median)</td><td>{stats.get('p50', 0):.4f}s</td></tr>
                        <tr><td>Average</td><td>{stats.get('avg', 0):.4f}s</td></tr>
                        <tr><td>p90</td><td>{stats.get('p90', 0):.4f}s</td></tr>
                        <tr><td>p95</td><td>{stats.get('p95', 0):.4f}s</td></tr>
                        <tr><td>p99</td><td>{stats.get('p99', 0):.4f}s</td></tr>
                        <tr><td>Max Latency</td><td>{stats.get('max', 0):.4f}s</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Outliers & Anomalies (<10% ratio)</h2>
                {f"<p style='color: var(--text-muted);'>No anomaly groups detected (all response categories were >= 10% of requests).</p>" if not outliers else ""}
                {"" if not outliers else "<table><thead><tr><th>Status</th><th>Size/Reason</th><th>Count</th><th>Ratio</th></tr></thead><tbody>"}
                {"".join(f"<tr><td class='status-err'>{html.escape(o['status'])}</td><td>{o['length']}</td><td>{o['count']}</td><td>{o['percentage']}</td></tr>" for o in outliers)}
                {"" if not outliers else "</tbody></table>"}
            </div>
        </div>

        <div class="card" style="margin-bottom: 2.5rem;">
            <h2>Response Times Over Execution</h2>
            <div class="chart-container">
                <canvas id="latencyChart"></canvas>
            </div>
        </div>

        <div class="card">
            <h2>Detailed Requests Log</h2>
            <div class="search-bar">
                <input type="text" id="searchInput" placeholder="Search requests (index, status, error)..." onkeyup="filterTable()">
            </div>
            <div class="scrollable">
                <table id="requestsTable">
                    <thead>
                        <tr>
                            <th>Index</th>
                            <th>Status Code</th>
                            <th>Reason/Error</th>
                            <th>Duration (s)</th>
                            <th>Length (bytes)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(
                            f"<tr>"
                            f"<td>{r['index']}</td>"
                            f"<td class='{('status-2xx' if 200<=r['status_code']<300 else 'status-3xx' if 300<=r['status_code']<400 else 'status-err') if r['status_code'] > 0 else 'status-err'}'>{r['status_code'] or 'ERROR'}</td>"
                            f"<td>{html.escape(r['reason'] or r['error'] or '')}</td>"
                            f"<td>{r['duration']:.4f}</td>"
                            f"<td>{r.get('length', 0)}</td>"
                            f"</tr>"
                            for r in results
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const rawData = {reqs_json};
        
        // Render Latency Chart
        const ctx = document.getElementById('latencyChart').getContext('2d');
        const labels = rawData.map(r => `Req ${{r.index}}`);
        const dataset = rawData.map(r => r.duration);
        
        new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [{{
                    label: 'Response Time (seconds)',
                    data: dataset,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: '#1f2937' }},
                        ticks: {{ color: '#9ca3af' }}
                    }},
                    x: {{
                        grid: {{ display: false }},
                        ticks: {{ color: '#9ca3af', maxRotation: 90, minRotation: 90 }}
                    }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});

        function filterTable() {{
            const input = document.getElementById("searchInput");
            const filter = input.value.toLowerCase();
            const table = document.getElementById("requestsTable");
            const tr = table.getElementsByTagName("tr");

            for (let i = 1; i < tr.length; i++) {{
                let match = false;
                const tds = tr[i].getElementsByTagName("td");
                for (let j = 0; j < tds.length; j++) {{
                    if (tds[j]) {{
                        const text = tds[j].textContent || tds[j].innerText;
                        if (text.toLowerCase().indexOf(filter) > -1) {{
                            match = true;
                            break;
                        }}
                    }}
                }}
                tr[i].style.display = match ? "" : "none";
            }}
        }}
    </script>
</body>
</html>
"""
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{Fore.GREEN}HTML Report successfully written to {html_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to write HTML Report: {e}{Style.RESET_ALL}\n")

def export_results(
    results: List[Dict[str, Any]],
    total_time: float,
    concurrency: int,
    output_path: str
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
    
    summary_data = {
        "total_requests": total,
        "concurrency": concurrency,
        "successful_requests": success_count,
        "failed_requests": fail_count,
        "total_time_sec": total_time,
        "requests_per_second": total / total_time if total_time > 0 else 0,
        "statistics": stats,
        "status_code_breakdown": status_counts
    }
    
    output_data = {
        "summary": summary_data,
        "requests": results
    }
    
    try:
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=4)
        print(f"{Fore.GREEN}Results successfully exported to {output_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to export results to {output_path}: {e}{Style.RESET_ALL}\n")

async def race(
    req_template: Dict[str, Any],
    concurrency: int,
    timeout: float,
    verify: bool,
    http2: bool,
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
    wordlist: List[str]
):
    limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency + 10)
    
    # Configure Proxy
    client_kwargs = {
        "http2": http2,
        "verify": verify,
        "limits": limits
    }
    if proxy:
        client_kwargs["proxy"] = proxy
        
    async with httpx.AsyncClient(**client_kwargs) as client:
        # Run warm-up requests if configured
        if warmup_count > 0:
            await run_warmup(client, req_template, warmup_count, warmup_delay)
            
        results = []
        start_event = asyncio.Event()
        
        pbar = None
        if has_tqdm:
            pbar = tqdm(total=concurrency, desc="Racing requests")
            
        tasks = []
        for i in range(concurrency):
            # Select payload cyclically from wordlist if wordlist loaded
            payload = wordlist[i % len(wordlist)] if wordlist else ""
            
            tasks.append(send_req(
                client=client,
                req_template=req_template,
                idx=i + 1,
                start_event=start_event,
                payload=payload,
                rate_limit=rate_limit,
                isolate_sessions=isolate_sessions,
                success_codes=success_codes,
                success_string=success_string,
                save_bodies_dir=save_bodies_dir,
                verbose=verbose,
                results=results,
                pbar=pbar
            ))
            
        print(f"{Fore.CYAN}Ready... Set... Go! Starting race for {concurrency} requests...{Style.RESET_ALL}")
        
        race_start_time = time.perf_counter()
        
        # Open the gate to release requests
        start_event.set()
        
        await asyncio.gather(*tasks)
        
        total_time = time.perf_counter() - race_start_time
        
        if pbar:
            pbar.close()
            print()
            
        print_summary(results, total_time, concurrency)
        
        if output_path:
            export_results(results, total_time, concurrency, output_path)
            
        if html_path:
            generate_html_report(results, total_time, concurrency, req_template, html_path)

def load_yaml(yaml_path: str) -> Dict[str, Any]:
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("YAML file must represent a dictionary structure")
    if 'method' not in data or 'url' not in data:
        raise ValueError("YAML file must contain 'method' and 'url' keys")
    return data

def main():
    parser = argparse.ArgumentParser(description="NFR - NEED FOR RACE")
    
    # Mutually exclusive group for inputs
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-y", "--yaml", help="Path to YAML configuration file")
    group.add_argument("-r", "--raw", help="Path to raw HTTP request file (e.g. copied from Burp)")
    
    parser.add_argument("--raw-http", action="store_true", help="Force HTTP protocol instead of HTTPS when parsing raw request")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrency level (overrides file config if present, default: 10)")
    parser.add_argument("-t", "--timeout", type=float, help="Request timeout in seconds (overrides file config if present, default: 10.0)")
    parser.add_argument("--verify", action="store_true", default=None, help="Enable SSL certification verification")
    parser.add_argument("--no-verify", action="store_false", dest="verify", help="Disable SSL certification verification (default)")
    parser.add_argument("--http2", action="store_true", default=None, help="Enable HTTP/2 support")
    parser.add_argument("--no-http2", action="store_false", dest="http2", help="Disable HTTP/2 support (default)")
    parser.add_argument("-w", "--warmup", type=int, help="Number of warm-up requests to execute (overrides file config if present, default: 3)")
    parser.add_argument("--no-warmup", action="store_const", const=0, dest="warmup", help="Disable warm-up requests")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full response headers and bodies")
    parser.add_argument("-o", "--output", help="Path to export JSON results file")
    
    # Phase 2 Options
    parser.add_argument("--proxy", help="Upstream HTTP/Socks proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--wordlist", help="Path to payload wordlist file to substitute {{payload}}")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Pace request releases to a maximum rate (RPS). default: 0 (unlimited)")
    parser.add_argument("--warmup-delay", type=float, default=0.0, help="Delay in seconds between sequential warmup requests. default: 0")
    parser.add_argument("--isolate-sessions", action="store_true", help="Isolate session states (empty cookie jar) per request")
    parser.add_argument("--success-code", help="Comma-separated status codes to determine success (e.g. 200,201)")
    parser.add_argument("--success-string", help="Body substring to search for to determine success")
    parser.add_argument("--save-bodies", help="Directory path to save full response bodies")
    parser.add_argument("--html", help="Path to write the interactive HTML report")
    
    args = parser.parse_args()

    # Load and parse file config
    if args.yaml:
        if not (args.yaml.endswith(".yaml") or args.yaml.endswith(".yml")):
            print_startup_error(
                stage="FILE VALIDATION",
                title="Invalid File Extension",
                details=f"The configuration file '{args.yaml}' must end with .yaml or .yml",
                hint="Rename your file to use a .yaml or .yml extension, or verify the file path."
            )
            sys.exit(1)
            
        try:
            req = load_yaml(args.yaml)
        except FileNotFoundError:
            print_startup_error(
                stage="FILE READ ERROR",
                title="File Not Found",
                details=f"The YAML configuration file '{args.yaml}' could not be located.",
                hint="Verify that the file path is correct and the file exists in the directory."
            )
            sys.exit(1)
        except yaml.YAMLError as ye:
            print_startup_error(
                stage="YAML PARSING ERROR",
                title="Malformed YAML Configuration",
                details=str(ye),
                hint="Verify your YAML syntax. Ensure you use spaces (not tabs) for indentation and that keys have a space after the colon (e.g. key: value)."
            )
            sys.exit(1)
        except Exception as e:
            print_startup_error(
                stage="CONFIG LOADING ERROR",
                title="Unexpected Error Loading YAML",
                details=str(e),
                hint="Check the format of your YAML file."
            )
            sys.exit(1)
            
    elif args.raw:
        try:
            req = parse_raw_request(args.raw, force_http=args.raw_http)
        except FileNotFoundError:
            print_startup_error(
                stage="FILE READ ERROR",
                title="File Not Found",
                details=f"The raw request file '{args.raw}' could not be located.",
                hint="Verify that the file path is correct and the file exists in the directory."
            )
            sys.exit(1)
        except ValueError as ve:
            print_startup_error(
                stage="RAW REQUEST PARSING ERROR",
                title="Malformed HTTP Request Format",
                details=str(ve),
                hint="Ensure you copy the entire raw HTTP request from Burp Suite, including the request line (e.g., 'POST /path HTTP/1.1') and the 'Host' header."
            )
            sys.exit(1)
        except Exception as e:
            print_startup_error(
                stage="RAW REQUEST PARSING ERROR",
                title="Unexpected Parsing Error",
                details=str(e),
                hint="Verify that the raw request is standard HTTP/1.1 text format."
            )
            sys.exit(1)

    # Validate target URL presence and scheme
    url = req.get("url")
    if not url:
        print_startup_error(
            stage="CONFIGURATION VALIDATION",
            title="Missing Target URL",
            details="The request configuration is missing a target URL.",
            hint="Make sure the 'url' property is set in the YAML file, or the raw request contains a valid Host header."
        )
        sys.exit(1)
    elif not (url.startswith("http://") or url.startswith("https://")):
        print_startup_error(
            stage="CONFIGURATION VALIDATION",
            title="Invalid Target URL Schema",
            details=f"URL '{url}' is invalid. The schema must be http:// or https://",
            hint="Ensure the URL starts with 'http://' or 'https://' or check your Host header/Request path formatting."
        )
        sys.exit(1)

    # Load Wordlist if configured
    wordlist = []
    if args.wordlist:
        try:
            wordlist = load_wordlist(args.wordlist)
        except Exception as e:
            print_startup_error(
                stage="WORDLIST LOADING",
                title="Failed to Load Wordlist",
                details=str(e),
                hint="Verify the wordlist file exists and is not empty."
            )
            sys.exit(1)

    # Parse Success Codes if configured
    success_codes = []
    if args.success_code:
        try:
            success_codes = [int(x.strip()) for x in args.success_code.split(",")]
        except Exception:
            print_startup_error(
                stage="ARGUMENT PARSING",
                title="Invalid Success Codes List",
                details=f"Could not parse success codes: '{args.success_code}'",
                hint="Provide a comma-separated list of integers, e.g. '--success-code 200,201'."
            )
            sys.exit(1)

    # Hierarchy: CLI arg > Config file > Default value
    concurrency = args.concurrency if args.concurrency is not None else req.get("concurrency", 10)
    timeout = args.timeout if args.timeout is not None else req.get("timeout", 10.0)
    verify = args.verify if args.verify is not None else req.get("verify", False)
    http2 = args.http2 if args.http2 is not None else req.get("http2", False)
    warmup_count = args.warmup if args.warmup is not None else req.get("warmup", 3)
    verbose = args.verbose
    
    # Store dynamic configurations inside req for send_req usage
    req["timeout"] = timeout

    print(f"{Fore.CYAN}NFR Race Configuration:{Style.RESET_ALL}")
    print(f"  Target URL:       {req['url']}")
    print(f"  Method:           {req['method']}")
    print(f"  Concurrency:      {concurrency}")
    print(f"  Timeout:          {timeout}s")
    print(f"  SSL Verify:       {verify}")
    print(f"  HTTP/2:           {http2}")
    print(f"  Warmup Requests:  {warmup_count} (delay: {args.warmup_delay}s)")
    if args.rate_limit > 0:
        print(f"  Rate Limit (RPS): {args.rate_limit}")
    if args.proxy:
        print(f"  Upstream Proxy:   {args.proxy}")
    if args.wordlist:
        print(f"  Wordlist File:    {args.wordlist} ({len(wordlist)} entries)")
    if args.isolate_sessions:
        print(f"  Isolate Sessions: True")
    if success_codes:
        print(f"  Success Codes:    {success_codes}")
    if args.success_string:
        print(f"  Success String:   '{args.success_string}'")
    if args.save_bodies:
        print(f"  Save Bodies Dir:  {args.save_bodies}")
    print(f"  Verbose Logging:  {verbose}")
    if args.output:
        print(f"  JSON Output:      {args.output}")
    if args.html:
        print(f"  HTML Report:      {args.html}")
    print()

    asyncio.run(race(
        req_template=req,
        concurrency=concurrency,
        timeout=timeout,
        verify=verify,
        http2=http2,
        warmup_count=warmup_count,
        warmup_delay=args.warmup_delay,
        rate_limit=args.rate_limit,
        isolate_sessions=args.isolate_sessions,
        success_codes=success_codes,
        success_string=args.success_string,
        save_bodies_dir=args.save_bodies,
        verbose=verbose,
        proxy=args.proxy,
        output_path=args.output,
        html_path=args.html,
        wordlist=wordlist
    ))

if __name__ == "__main__":
    main()