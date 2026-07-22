# NFR - Need For Race

An asynchronous HTTP race condition and concurrency testing framework written in Python. Designed for security researchers and developers to test web applications for race conditions, single-use voucher exploits, double-spending vulnerabilities, and state synchronization flaws with microsecond-level accuracy.

---

## Key Features

*   **HTTP/2 Single-Packet Attack (Last-Byte Synchronization)**: Implements PortSwigger's Last-Byte Synchronization technique over HTTP/2. Pre-stages N request streams on a single TCP connection minus the final payload byte, then transmits all final bytes together in a single TCP write frame to achieve microsecond-level concurrent arrival at the target host.
*   **Multi-Account Session Pool Rotation (`--sessions`)**: Rotates session tokens and cookies from a text, JSON, or YAML file across request threads. Ideal for testing multi-user race scenarios (for example, User A transferring balance to User B simultaneously, or two users claiming the same single-use coupon).
*   **Automated Differential Anomaly Engine**: Executes an automated baseline request (N=1) prior to the race burst. Automatically detects and flags anomalies:
    *   **Duplicate Successes**: Multiple HTTP 2xx responses when only one success was expected.
    *   **Response Length Outliers**: Response body sizes deviating by more than 10% from baseline.
    *   **Database Lock Timeouts**: High latency spikes (greater than 3x baseline) or HTTP 500/504 status codes indicating database row lock contention.
*   **Smart Template and Dynamic Expression Engine**:
    *   `{{payload}}` or `${payload}`: Wordlist payload injection
    *   `${time.now_iso()}`: ISO-8601 UTC timestamp
    *   `${hash.sha256(index)}` or `${hash.md5(seq)}`: SHA-256 / MD5 hashes of request sequence
    *   `${random_ip()}`: Random IPv4 address for dynamic `X-Forwarded-For` header rotation
    *   `${random_str(N)}` or `{{random_str:N}}`: Random alphanumeric string of length N
    *   `{{random_int}}` or `${math.random()}`: Random 6-digit integer
    *   `{{uuid}}` or `${uuid()}`: Random UUID v4
    *   `{{urlencode(...)}}`: URL-encodes inner content
*   **Structured Multi-Format Reporting**:
    *   **JSON Report (`-o report.json`)**: Raw request/response data and summary statistics.
    *   **Interactive HTML Report (`--html report.html`)**: Interactive dashboard with latency distribution graphs.
    *   **SARIF v2.1.0 Report (`--sarif report.sarif`)**: Standard format for Bug Bounty and vulnerability management platforms (HackerOne, Bugcrowd, DefectDojo, GitHub Security).
*   **Global CLI Packaging**: Packageable via `pyproject.toml` or runnable via the `nfr` command line tool.

---

## Installation

### Method 1: Standard Installation
```bash
git clone https://github.com/Asbawy/NFR.git
cd NFR
pip install -r requirements.txt
```

### Method 2: Editable PyPI CLI Package
```bash
pip install -e .
nfr --raw request.txt -c 20 --http2-sync
```

### Method 3: Standalone Executable Binary
Build a standalone binary using PyInstaller:

Windows (PowerShell):
```powershell
.\build.ps1
```

Linux / macOS (Bash):
```bash
chmod +x build.sh
./build.sh
```

The compiled binary will be placed at `dist/nfr.exe` (Windows) or `dist/nfr` (Linux/macOS).

---

## Input Formats

NFR supports two input formats for defining requests:

### 1. Raw HTTP Request (Burp Suite Format)
Copy a raw request directly from Burp Suite into a file (e.g., `request.txt`):

```http
POST /api/v1/coupon/claim?uid=${uuid()} HTTP/1.1
Host: target.example.com
Authorization: Bearer bearer_token_here
X-Request-ID: req-${hash.sha256(index)}
X-Forwarded-For: ${random_ip()}
Content-Type: application/json

{
  "code": "PROMO2026",
  "nonce": "${random_str(12)}"
}
```

### 2. YAML Configuration File
Alternatively, define the request in a YAML file (e.g., `req.yaml`):

```yaml
method: POST
url: https://target.example.com/api/v1/coupon/claim?uid=${uuid()}
headers:
  Host: target.example.com
  Authorization: Bearer bearer_token_here
  X-Request-ID: req-${hash.sha256(index)}
  Content-Type: application/json
body:
  code: "PROMO2026"
  nonce: "${random_int()}"
```

---

## Template Variables Reference

| Variable / Function | Description | Example Output |
| :--- | :--- | :--- |
| `{{payload}}` / `${payload}` | Substituted with item from `--wordlist`. | `admin` |
| `${time.now_iso()}` | Current ISO-8601 UTC timestamp. | `2026-07-22T06:15:00+00:00` |
| `{{timestamp}}` / `${timestamp()}` | Unix timestamp in milliseconds. | `1784697300000` |
| `{{uuid}}` / `${uuid()}` | Random Version 4 UUID. | `f47ac10b-58cc-4372-a567-0e02b2c3d479` |
| `{{index}}` / `${index()}` | Request sequence number (1..N). | `5` |
| `${hash.sha256(index)}` | SHA-256 hash of sequence index or string. | `ef2d127de37b942baad06145e...` |
| `${hash.md5(index)}` | MD5 hash of sequence index or string. | `e10adc3949ba59abbe56e057f20f883e` |
| `${random_ip()}` | Random IPv4 address (for `X-Forwarded-For`). | `192.0.2.45` |
| `${random_str(N)}` | Random alphanumeric string of length N. | `aB9xK2mP1z` |
| `{{random_int}}` / `${math.random()}` | Random 6-digit integer. | `482910` |
| `{{urlencode(...)}}` | URL-encodes the enclosed text. | `%20hello%20` |

---

## Usage Examples

### Example 1: Basic Race Condition Test
Run 30 concurrent requests using a raw HTTP request:
```bash
python NFR.py --raw request.txt --concurrency 30 --html report.html
```

### Example 2: HTTP/2 Single-Packet Attack (Last-Byte Synchronization)
Perform microsecond-level single-packet synchronization over an HTTP/2 connection:
```bash
python NFR.py --raw request.txt --concurrency 30 --http2-sync --sarif results.sarif
```

### Example 3: Multi-Account Race Testing
Create a `sessions.txt` file containing tokens or cookie headers (one per line):
```text
Bearer token_user_A
Bearer token_user_B
Bearer token_user_C
```

Run a multi-account race test:
```bash
python NFR.py --raw request.txt --concurrency 30 --sessions sessions.txt
```

### Example 4: Fuzzing with Payload Wordlist and Proxy
Route requests through an upstream proxy (e.g., Burp Suite) while substituting payloads from a wordlist:
```bash
python NFR.py --raw request.txt --concurrency 20 --wordlist payloads.txt --proxy http://127.0.0.1:8080 -o output.json
```

### Example 5: SARIF Reporting for Security Platforms
Export results in SARIF v2.1.0 format for direct import into HackerOne, Bugcrowd, or GitHub Security:
```bash
python NFR.py --yaml req.yaml --concurrency 50 --sarif bugbounty_report.sarif
```

---

## CLI Command Line Reference

### Input Configuration
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--raw` | `-r` | Path to raw HTTP request file (Burp Suite format). | None |
| `--yaml` | `-y` | Path to YAML request configuration file. | None |
| `--raw-http` | - | Force HTTP protocol instead of HTTPS when parsing raw request. | HTTPS |

### Concurrency and Engine Control
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--concurrency` | `-c` | Concurrency level (number of requests). | `10` |
| `--http2-sync` | `--h2-sync` | Enable HTTP/2 Last-Byte Synchronization (Single-Packet Attack). | Disabled |
| `--http2` | - | Enable standard HTTP/2 multiplexing. | Disabled |
| `--baseline` / `--no-baseline` | - | Execute pre-race baseline request (N=1) for differential analysis. | Enabled |
| `--sessions` | - | Path to session pool file (`.txt`, `.json`, `.yaml`) for multi-account testing. | None |
| `--wordlist` | - | Path to payload wordlist file for `{{payload}}`. | None |
| `--timeout` | `-t` | Request timeout in seconds. | `10.0` |
| `--warmup` | `-w` | Number of pre-flight warm-up requests to execute. | `3` |
| `--warmup-delay` | - | Delay in seconds between sequential warm-up requests. | `0.0` |
| `--rate-limit` | - | Pace request releases to a maximum rate (Requests Per Second). | `0.0` (unlimited) |
| `--isolate-sessions` | - | Isolate cookie jars per request. | Shared |
| `--proxy` | - | Upstream HTTP/Socks proxy URL (e.g., `http://127.0.0.1:8080`). | None |

### Criteria and Output Filtering
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--success-code` | - | Comma-separated HTTP status codes to determine success (e.g., `200,201`). | None |
| `--success-string` | - | Response body substring to search for to determine success. | None |

### Output and Reporting
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--sarif` | - | Path to export SARIF v2.1.0 report file. | None |
| `--html` | - | Path to write interactive HTML report dashboard. | None |
| `--output` | `-o` | Path to export JSON results file. | None |
| `--save-bodies` | - | Directory path to save full response bodies. | None |
| `--verbose` | `-v` | Show full request/response headers and body content in console. | Disabled |

---

## License

MIT License. Created by Asbawy.
