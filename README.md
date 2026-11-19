# Veracode Portfolio Report (Reporting API)

Portfolio-wide review of a Veracode tenant from the [Reporting REST API](https://docs.veracode.com/r/Reporting_REST_API): one FINDINGS report and one SCANS report cover every application, and the script turns them into a summary plus CSVs.

For a complete, per-finding export (every scan type, links, sandboxes), use [Veracode-All-Findings-Extract](https://github.com/ancient-cthulhu/Veracode-All-Findings-Extract) instead.

> [!IMPORTANT]
> The Reporting API only returns objects updated in the last six months. An open finding that was not re-found, fixed or mitigated in that time does not appear, so backlog counts here are a floor, not a total.

## Setup

1. Ask support@veracode.com to enable the Reporting API for your organization.
2. Use one of:
   - API service account with the **Reporting API** role (add **Results API** to include apps with no recent activity, see `--no-inventory`).
   - User account with **Executive**, **Security Lead** or **Security Insights** (Security Insights only sees its own teams).
3. Create **HMAC** API credentials (OAuth credentials return 401) and set:
   ```bash
   export VERACODE_API_ID=...
   export VERACODE_API_KEY=...
   ```
   Or use `~/.veracode/credentials` (`[default]`, `veracode_api_key_id`, `veracode_api_key_secret`). `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` also work.
4. Install: `pip install -r requirements.txt` (Python 3.10+).

The region (US, EU, FedRAMP) comes from the API ID (environment or credentials file). Set `VERACODE_API_BASE` to override.

## Run

```bash
python portfolio_report.py                         # last six months, policy scans
python portfolio_report.py --start-date 2026-09-01 # shorter window
python portfolio_report.py --include-sandbox       # add sandbox findings and scans
```

Each run:

1. Requests a FINDINGS and a SCANS report for the window, waits for both and reads every page.
2. Lists all applications through the Applications API (skipped with a warning if the account lacks access).
3. Removes duplicate rows and writes the files below to `portfolio_report/`.

## Output

| File | Content |
|---|---|
| `PORTFOLIO.md` | Summary, severity (open, fixed, median days to fix, age), riskiest apps, business units, monthly trend, overdue findings, top CWEs, open SCA findings by library (with the fixed or safe version when known), mitigations awaiting a decision, scan coverage |
| `applications.csv` | One row per app: open by severity, policy violations, overdue, fixed, pending mitigations, median days to fix, last scan, compliance |
| `findings.csv` | One row per finding, with `overdue`, `days_open`, `days_to_fix`, `fixed_in_window`, `mitigation_pending` added |
| `scans.csv` | One row per scan |
| `raw_*.json` | Raw report rows as returned by the API, with `--raw-json` |

Definitions:

| Term | Meaning |
|---|---|
| Overdue | Open, violates policy, grace period expiry date has passed |
| Fixed in window | Closed, with a `fixed_date` inside the window (a reopened finding is not fixed) |
| Days to fix | `found_date` to `fixed_date`, closed findings only; medians use fixes in the window |
| Mitigation awaiting decision | Last proposal is newer than the last accept or reject |
| Last scan | Latest policy scan in the window, else the last completed scan from the app inventory |
| Compliance | The app's current policy status from the app inventory, else the latest policy scan in the window |

## Options

| Option | Default | Description |
|---|---|---|
| `--start-date` | six months ago | `YYYY-MM-DD`; older dates are rejected |
| `--end-date` | today | `YYYY-MM-DD`, inclusive |
| `--output-dir` | `portfolio_report` | Output folder |
| `--include-sandbox` | off | Include sandbox findings and scans |
| `--stale-days` | 90 | Flag apps with no scan in N days |
| `--top` | 20 | Rows per ranked table |
| `--no-inventory` | off | Skip the Applications API call |
| `--raw-json` | off | Save raw report rows |
| `--poll-interval` | 10 | Initial seconds between status checks (backs off to 60) |
| `--timeout` | 60 | Minutes to wait per report |
| `-v` | off | Debug logging |

## Troubleshooting

| What you see | Fix |
|---|---|
| `HTTP 401/403` on create report | Check the role, that the Reporting API is enabled, HMAC (not OAuth) credentials, and the region |
| `--start-date ... more than six months ago` | Use a later date, or the Findings API export for older data |
| `Applications API returned 403; skipping inventory` | Add the Results API role, or run with `--no-inventory` |
| `not completed after ...` | Raise `--timeout`; large tenants can take a while |
| `page N of M came back empty` | The report was incomplete when read (results are not written); run again |
