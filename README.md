# Cybersecurity Log Analyzer

A small defensive Python command-line tool for analyzing synthetic authentication logs and identifying repeated failed login attempts by IP address.

> This is an educational portfolio project. Use it only with synthetic data or logs you are explicitly authorized to analyze.

## What it does

- Validates ISO 8601 timestamps and IP addresses.
- Accepts `login_failed` and `login_success` events.
- Counts valid events by type.
- Counts failed logins by IP address.
- Flags an IP as suspicious when it reaches three or more failed logins by default.
- Skips malformed records and reports how many were ignored.
- Prints a deterministic JSON report for easy inspection or future automation.

## Safe use cases

You can use this project to:

- Practice Python parsing, validation, data structures, and testing.
- Study how authentication events can be summarized defensively.
- Analyze synthetic logs created for training.
- Review exported logs from a system where you have explicit authorization.
- Demonstrate a basic defensive-security workflow in a portfolio.

## What it must not be used for

Do not use this tool to:

- Access, monitor, or investigate systems without permission.
- Collect passwords, tokens, or other credentials.
- Probe, scan, exploit, or attack networks or services.
- Treat the result as a complete SIEM, intrusion-detection system, or incident response decision.
- Upload real logs or sensitive data to this repository.

## How it works

1. Read a local UTF-8 log file line by line.
2. Validate the timestamp, event type, username, and IP address.
3. Count valid successful and failed logins.
4. Count failed logins for each IP address.
5. Mark IPs that meet the configured threshold.
6. Return a JSON report and the number of malformed lines.

## Input format

Each line must follow this format:

```text
ISO_TIMESTAMP EVENT user=USERNAME ip=IP
```

Example:

```text
2026-10-01T10:00:00+00:00 login_failed user=alice ip=203.0.113.10
2026-10-01T10:01:00+00:00 login_success user=bob ip=198.51.100.7
```

The sample uses documentation-only IP ranges and does not represent real users.

## Requirements

- Python 3.11 or newer.
- No runtime dependency outside the Python standard library.

## Setup

Create and activate a virtual environment, then install the project in editable mode:

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --editable .
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --editable .
```

## Usage

Analyze the included synthetic sample:

```bash
python -m cybersecurity_log_analyzer.cli samples/auth.log --threshold 3
```

`--threshold` controls how many failed attempts from one IP are required before it is listed as suspicious. The default is `3`.

## Example output

```json
{
  "failed_attempts": 4,
  "failed_by_ip": {
    "192.0.2.44": 1,
    "203.0.113.10": 3
  },
  "malformed_lines": 0,
  "successful_logins": 1,
  "suspicious_ips": [
    "203.0.113.10"
  ],
  "total_entries": 5
}
```

## Understanding the report

- `total_entries`: valid authentication records processed.
- `failed_attempts`: valid `login_failed` records.
- `successful_logins`: valid `login_success` records.
- `failed_by_ip`: failed-login count grouped by IP.
- `suspicious_ips`: IPs at or above the configured threshold.
- `malformed_lines`: records skipped because they did not pass validation.

## Testing

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The same test suite runs automatically in GitHub Actions for pushes and pull requests.

## Project structure

```text
src/cybersecurity_log_analyzer/  parser, aggregation, and CLI
tests/                           automated behavior tests
samples/                         synthetic input data only
.github/workflows/               continuous integration
```

## Limitations and roadmap

This first version supports one deliberately small log format, local files, and a simple repeated-failure rule. It does not correlate events across systems, make incident-response decisions, or replace professional security tooling.

Possible future improvements include additional authorized log formats, CSV export, richer time-window analysis, and more defensive test fixtures.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
