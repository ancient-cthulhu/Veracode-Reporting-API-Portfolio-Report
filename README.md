# Veracode Portfolio Report (Reporting API)

Portfolio-wide review of a Veracode tenant from the [Reporting REST API](https://docs.veracode.com/r/Reporting_REST_API): one FINDINGS report and one SCANS report cover every application, and the script turns them into a summary plus CSVs.

For a complete, per-finding export (every scan type, links, sandboxes), use [Veracode-All-Findings-Extract](https://github.com/ancient-cthulhu/Veracode-All-Findings-Extract) instead.

> [!IMPORTANT]
> The Reporting API only returns objects updated in the last six months. An open finding that was not re-found, fixed or mitigated in that time does not appear, so backlog counts here are a floor, not a total.

## Setup

1. Ask support@veracode.com to enable the Reporting API for your organization.
2. Use one of:
   - API service account with the **Reporting API** role (add **Results API** for apps with no recent activity, teams, business criticality and scan types; see `--no-inventory`).
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
| `PORTFOLIO.md` | Executive report, sections below |
| `applications.csv` | One row per app: risk score, open by severity, overdue, debt, fixed, pending mitigations, median days to fix, scan types, last scan, policy status |
| `findings.csv` | One row per finding, with `overdue`, `days_open`, `days_to_fix`, `fixed_in_window`, `mitigation_pending` added |
| `scans.csv` | One row per scan |
| `raw_*.json` | Raw report rows as returned by the API, with `--raw-json` |

`PORTFOLIO.md` sections:

| Section | Shows |
|---|---|
| Scorecard | Policy pass rate, scan recency, flaw prevalence, fix capacity, fix speed, fix-by adherence, open Very High/High, overdue, security debt, pending mitigations, with Veracode SoSS 2025 benchmarks |
| Key takeaways | Generated from the numbers: riskiest apps, fix capacity vs benchmark, missed fix-by dates, unscanned apps, critical debt |
| Trend by month | New vs fixed flaws, net change, fix ratio, scans, apps scanned |
| Open flaws by severity and age | Age buckets (0-30 to 365+ days), median and P90 days to fix |
| Applications needing attention | Ranked by risk score |
| Business units / Teams | Per group: policy pass rate, scan recency, open VH/H, overdue, debt, fix capacity, days to fix. **Shown only if the tenant uses them** |
| Scan coverage | Apps per scan type (SAST, SCA, DAST, Manual), coverage by business criticality, apps not scanned recently |
| Overdue findings | Past their policy fix-by date, worst first |
| Weaknesses / Open-source risk | Top CWEs in first-party code; vulnerable libraries with the version to upgrade to |
| Mitigations | Awaiting a decision, accepted and rejected in the window |

Business units count as used when any app has one other than "Not Specified"; teams when any app has a team (teams and criticality come from the app inventory). Unused groupings are left out of the report and the CSVs.

Definitions:

| Term | Meaning |
|---|---|
| Flaw prevalence | Share of apps with a policy scan in the window that have at least one open flaw |
| Fix capacity | Flaws fixed per month as a share of open + fixed flaws |
| Fix speed (half-life) | Days until half the flaws first found in the window are fixed; open flaws count at their current age |
| Fixed by fix-by date | Of findings whose policy grace period ended in the window, the share fixed by then |
| Overdue | Open, violates policy, grace period expiry date has passed |
| Security debt | Open flaws first found over a year ago; critical debt is Very High/High |
| Fixed in window | Closed, with a `fixed_date` inside the window (a reopened finding is not fixed) |
| Days to fix | `found_date` to `fixed_date`, fixes in the window |
| Risk score | (10 x open VH + 5 x open H + 3 x overdue + 2 x debt) x criticality weight (Very High 2, High 1.5, Medium 1, Low 0.75, Very Low 0.5) |
| Mitigation awaiting decision | Last proposal is newer than the last accept or reject |
| Last scan | Latest policy scan in the window, else the last completed scan from the app inventory |
| Policy | The app's current policy status from the app inventory, else the latest policy scan in the window |

Benchmarks (Veracode State of Software Security 2025): flaw prevalence leaders below 43%, laggards 86%; fix capacity leaders 10%+ a month, laggards about 1%; half-life leaders about five weeks, laggards over a year.

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
