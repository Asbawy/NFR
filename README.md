# NFR - Need For Race

An asynchronous HTTP race condition testing tool written in Python. It allows developers and security researchers to test web applications for concurrency bugs and race conditions with precise synchronization, wordlist fuzzing, and reporting.

You can specify the request using:
1. **Raw HTTP Request File** (e.g. copied from Burp Suite)
2. **YAML Configuration File**

---

## Features

*   **Synchronization Gate**: Blocks all requests and releases them simultaneously to maximize the chance of race conditions.
*   **Burp Suite Request Support**: Parses raw HTTP request text files directly.
*   **Connection Warm-up**: Pre-establishes TCP/TLS connections to avoid initial latency skew.
*   **Template Placeholders**: Dynamically renders variables in the request:
    *   `{{random_int}}` - Random 6-digit integer
    *   `{{timestamp}}` - Millisecond Unix timestamp
    *   `{{uuid}}` - Random UUID v4
    *   `{{index}}` / `{{seq}}` - Request sequence index
    *   `{{random_str:N}}` - Random alphanumeric string of length N
    *   `{{urlencode(value)}}` - URL-encodes a value
*   **Wordlist Fuzzing**: Injects words using a `--wordlist` file and the `{{payload}}` placeholder.
*   **Rate Limiting**: Throttles request releases to a maximum Requests Per Second (RPS) limit.
*   **Session Isolation**: Separates cookie jars per request.
*   **Anomaly Detection**: Groups responses by code/size to identify outliers (response categories under 10% ratio).
*   **HTML & JSON Reports**: Generates JSON results and interactive HTML report dashboards.
*   **Response Archiver**: Saves response body files to a specified directory.
*   **Upstream Proxy**: Routes requests through a proxy (e.g. Burp Suite).

---

## Installation

```bash
git clone https://github.com/Asbawy/NFR.git
cd NFR
pip install -r requirements.txt
```

---

## Usage

### Method 1: Raw HTTP Request (Recommended)
Save a raw HTTP request to `request.txt`:

```http
POST /api/coupon/claim?uid={{uuid}} HTTP/1.1
Host: example.com
Authorization: Bearer token
X-Request-Id: req-{{timestamp}}-{{index}}
Content-Type: application/json
Content-Length: 75

{
  "coupon_code": "WELCOME2026",
  "nonce": "{{random_str:10}}",
  "email": "user+{{payload}}@example.com"
}
```

Run the tool:

```bash
python NFR.py --raw request.txt --concurrency 50 --wordlist payloads.txt --proxy http://127.0.0.1:8080 --html report.html
```

### Method 2: YAML Configuration
Create `req.yaml`:

```yaml
method: POST
url: https://example.com/api/coupon/claim?uid={{uuid}}
headers:
  Host: example.com
  Authorization: Bearer token
  X-Request-Id: req-{{timestamp}}-{{index}}
body:
  coupon_code: "WELCOME2026"
  nonce: "{{random_int}}"
```

Run the tool:

```bash
python NFR.py --yaml req.yaml --concurrency 50 --warmup 3
```

---

## CLI Options

### Configuration Input
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--yaml` | `-y` | Path to YAML request configuration file. | - |
| `--raw` | `-r` | Path to raw HTTP request file. | - |
| `--raw-http` | - | Force HTTP instead of HTTPS when parsing raw request. | HTTPS |

### Connection & Concurrency Control
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--concurrency`| `-c` | Concurrency level (number of requests). | `10` |
| `--timeout` | `-t` | HTTP request timeout in seconds. | `10.0` |
| `--verify` / `--no-verify` | - | Enable/Disable SSL certificate verification. | Disabled |
| `--http2` / `--no-http2` | - | Enable/Disable HTTP/2 support. | Disabled |
| `--warmup` | `-w` | Number of warmup requests to run first. | `3` |
| `--warmup-delay`| - | Delay in seconds between warmup requests. | `0.0` |
| `--rate-limit` | - | Pace request releases to a maximum rate (RPS). | `0` (unlimited) |
| `--isolate-sessions`| - | Isolate cookie jars per request. | Shared |

### Testing & Exploitation
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--proxy` | - | Upstream HTTP/Socks proxy URL (e.g. `http://127.0.0.1:8080`). | - |
| `--wordlist` | - | Path to wordlist payloads file. | - |
| `--success-code`| - | Comma-separated status codes to determine success. | - |
| `--success-string`| - | Body substring to search for to determine success. | - |

### Logging & Output
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--verbose` | `-v` | Show full request & response headers and body content. | Disabled |
| `--save-bodies`| - | Directory path to save response bodies. | Disabled |
| `--output` | `-o` | Path to export JSON results. | Disabled |
| `--html` | - | Path to write the HTML report. | Disabled |

---

## Example Output

```text
NFR Race Configuration:
  Target URL:       https://example.com/api/coupon/claim
  Method:           POST
  Concurrency:      15
  Timeout:          10.0s
  SSL Verify:       False
  HTTP/2:           False
  Warmup Requests:  3 (delay: 0.0s)
  Success Codes:    [200]
  Verbose Logging:  False

Performing 3 warm-up request(s) to establish connections...
  Warm-up 1/3 -> 200 OK (0.1240s)
  Warm-up 2/3 -> 200 OK (0.0542s)
  Warm-up 3/3 -> 200 OK (0.0528s)
Warm-up completed.

Ready... Set... Go! Starting race for 15 requests...
Racing requests: 100%|████████████████████████████████| 15/15 [00:00<00:00, 19.82it/s]

request   1 -> 200 OK (0.0541s) [SUCCESS]
request   2 -> 200 OK (0.0543s) [SUCCESS]
request   3 -> 409 Conflict (0.0548s) [FAILED]
...
request  15 -> 409 Conflict (0.0581s) [FAILED]

============================================================
                    RACE RESULTS SUMMARY
============================================================
Total Requests:     15
Concurrency:        15
Successful:         15
Failed:             0
Total Race Time:    0.7602s
Requests/Second:    19.73 RPS
------------------------------------------------------------
       Response Time Statistics (Successful Requests)
------------------------------------------------------------
Min:                0.0541s
Max:                0.0581s
Average:            0.0558s
p50 (Median):       0.0554s
p90:                0.0578s
p95:                0.0580s
p99:                0.0581s
------------------------------------------------------------
                   Status Code Breakdown
------------------------------------------------------------
200 OK                                   : 2
409 Conflict                             : 13
------------------------------------------------------------
          DETECTED ANOMALIES / OUTLIERS (<10% ratio)
------------------------------------------------------------
Group: Status 200 OK | Length: 120 bytes
  Count: 2 requests (13.33%)
  Request Indices: 1, 2
============================================================
```
