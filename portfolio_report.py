"""Veracode portfolio review built on the Reporting (Analytics) REST API.

One FINDINGS report and one SCANS report cover the whole tenant. The script
deduplicates them and writes a portfolio summary (PORTFOLIO.md) plus CSVs per
finding, scan and application.

The Reporting API only returns objects updated in the last six months. Use the
Findings API (Veracode-All-Findings-Extract) for a complete, per-finding backlog.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import email.utils
import json
import logging
import math
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import requests
from veracode_api_signing.credentials import get_credentials
from veracode_api_signing.exceptions import VeracodeCredentialsError
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

log = logging.getLogger("portfolio_report")

REPORT_PATH = "/appsec/v1/analytics/report"
APPS_PATH = "/appsec/v1/applications"
HOSTS = {"e": "https://api.veracode.eu", "f": "https://api.veracode.us"}
DEFAULT_HOST = "https://api.veracode.com"

SEVERITY_NAMES = {5: "Very High", 4: "High", 3: "Medium", 2: "Low", 1: "Very Low", 0: "Informational"}
RUNNING_STATES = {"QUEUED", "SUBMITTED", "PROCESSING"}
HTTP_TIMEOUT = (10, 120)
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 6

FINDING_COLUMNS = [
    "app_id", "app_name", "business_unit", "policy_sandbox", "sandbox_id", "scan_type",
    "finding_id", "flaw_id", "severity", "severity_name", "custom_severity", "status",
    "policy_rule_passed", "grace_period_expiry_date", "overdue", "cwe_id", "category_name",
    "flaw_name", "cve_id", "nvd_cvss3_score", "exploitability", "filename", "source_file_line",
    "module_name", "component_name", "component_version", "fixed_library_version",
    "library_latest_safe_version", "fixable", "project_name", "found_date", "last_found_date",
    "fixed_date", "resolved_date", "reopened_date", "days_open", "days_to_fix", "fixed_in_window",
    "resolution_status", "resolution", "mitigation_status", "mitigation_pending",
    "mitigation_last_proposed_date", "mitigation_last_accepted_date",
    "mitigation_last_rejected_date", "latest_scan_name", "last_updated_date",
]
SCAN_COLUMNS = [
    "app_id", "app_name", "business_unit", "scan_id", "scan_type", "scan_name", "policy_sandbox",
    "sandbox_name", "scan_policy", "scan_policy_compliance", "scan_state", "submitted", "published",
    "most_recent_scan", "veracode_level", "score", "num_new_flaws", "num_fixed_flaws",
    "num_all_flaws", "primary_language", "lines_scanned", "scan_time_seconds", "submitter_name",
]
APP_COLUMNS = [
    "app_id", "app_name", "business_unit", "teams", "business_criticality", "risk_score", "open",
    "open_very_high", "open_high", "open_policy_violations", "overdue", "security_debt",
    "fixed_in_window", "mitigations_pending", "median_days_to_fix", "scan_types", "last_scan",
    "days_since_scan", "policy_compliance", "veracode_level",
]
COUNT_COLUMNS = ("open", "open_very_high", "open_high", "open_policy_violations", "overdue",
                 "security_debt", "fixed_in_window", "mitigations_pending")


# --------------------------------------------------------------------------- setup

def load_credentials_env() -> None:
    """Accept VERACODE_API_ID / VERACODE_API_KEY (the names used across these tools)."""
    for src, dst in (("VERACODE_API_ID", "VERACODE_API_KEY_ID"),
                     ("VERACODE_API_KEY", "VERACODE_API_KEY_SECRET")):
        if os.environ.get(src) and not os.environ.get(dst):
            os.environ[dst] = os.environ[src]


def api_base() -> str:
    """Region from the API ID prefix (vera01ei-... -> EU); VERACODE_API_BASE overrides."""
    override = os.environ.get("VERACODE_API_BASE")
    if override:
        return override.rstrip("/")
    key_id = os.environ.get("VERACODE_API_KEY_ID") or _credentials_file_key_id()
    if "-" in key_id and len(key_id.split("-", 1)[0]) >= 7:
        return HOSTS.get(key_id.split("-", 1)[0][6].lower(), DEFAULT_HOST)
    return DEFAULT_HOST


def _credentials_file_key_id() -> str:
    """API ID from ~/.veracode/credentials (VERACODE_API_PROFILE honoured); only the ID is kept."""
    try:
        return get_credentials()[0] or ""
    except VeracodeCredentialsError:  # no usable file; the signing plugin reports it on first call
        return ""


def create_session() -> requests.Session:
    session = requests.Session()
    session.auth = RequestsAuthPluginVeracodeHMAC()
    session.headers["User-Agent"] = "veracode-portfolio-report"
    return session


def _retry_after(resp: requests.Response) -> float | None:
    """Retry-After in seconds (delta-seconds or HTTP-date form)."""
    raw = (getattr(resp, "headers", None) or {}).get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        return max(0.0, email.utils.parsedate_to_datetime(raw).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


def send(session: requests.Session, method: str, url: str, **kwargs: Any) -> requests.Response:
    """One API call with retries on 429/5xx and network errors, honouring Retry-After.

    Retries happen here, not in a urllib3 Retry, so each attempt is re-signed: a urllib3
    retry resends the same HMAC timestamp and nonce, which the API can reject as a replay.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        delay = float(min(2 ** attempt, 60))
        try:
            resp = session.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            log.warning("%s %s: %s; retry %d/%d in %.0fs", method, url, type(exc).__name__,
                        attempt, MAX_ATTEMPTS - 1, delay)
        else:
            if resp.status_code not in RETRY_STATUSES or attempt == MAX_ATTEMPTS:
                return resp
            wait = _retry_after(resp)
            delay = min(wait if wait is not None else delay, 300.0)
            log.warning("%s %s: HTTP %s; retry %d/%d in %.0fs", method, url, resp.status_code,
                        attempt, MAX_ATTEMPTS - 1, delay)
        time.sleep(delay)
    raise AssertionError("unreachable")


def check_response(resp: requests.Response, what: str) -> dict:
    if resp.status_code in (401, 403):
        raise SystemExit(
            f"{what}: HTTP {resp.status_code}. Check the credentials, the region, and that the "
            "account has the Reporting API role (API user) or Executive/Security Lead (UI user), "
            "and that Veracode Support enabled the Reporting API for your organization."
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"{what}: HTTP {resp.status_code}: {resp.text[:500]}")
    return resp.json()


# --------------------------------------------------------------------------- dates

def six_months_ago(today: dt.date) -> dt.date:
    year, month = (today.year, today.month - 6) if today.month > 6 else (today.year - 1, today.month + 6)
    for day in (today.day, 30, 29, 28):
        try:
            return dt.date(year, month, day)
        except ValueError:
            continue
    raise AssertionError("unreachable")


def resolve_window(start: str | None, end: str | None, today: dt.date) -> tuple[dt.date, dt.date]:
    end_date = dt.date.fromisoformat(end) if end else today
    earliest = six_months_ago(today) + dt.timedelta(days=1)
    start_date = dt.date.fromisoformat(start) if start else earliest
    if start_date < earliest:
        raise SystemExit(
            f"--start-date {start_date} is more than six months ago. The Reporting API only "
            f"returns data updated since {earliest}. Use the Findings API for older findings."
        )
    if start_date > end_date:
        raise SystemExit("--start-date must be on or before --end-date")
    return start_date, end_date


def parse_date(value: Any) -> dt.date | None:
    """Reporting API dates look like '2025-02-18 15:34:12.283' (EDT); day precision is enough."""
    if not value or not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------- reporting API

def request_report(session: requests.Session, base: str, payload: dict) -> str:
    data = check_response(send(session, "POST", base + REPORT_PATH, json=payload),
                          f"Create {payload['report_type']} report")
    report_id = data.get("id") or data.get("_embedded", {}).get("id")
    if not report_id:
        raise RuntimeError(f"No report id in response: {json.dumps(data)[:500]}")
    return report_id


def _page_count(data: dict) -> int | None:
    embedded = data.get("_embedded", {})
    for meta in (data.get("page_metadata"), data.get("page"), embedded.get("page_metadata"),
                 embedded.get("page")):
        if isinstance(meta, dict) and meta.get("total_pages") is not None:
            return int(meta["total_pages"])
    return None


def _has_next_link(data: dict) -> bool:
    for links in (data.get("_links"), data.get("_embedded", {}).get("_links")):
        if isinstance(links, dict) and links.get("next"):
            return True
    return False


def fetch_report(session: requests.Session, base: str, report_id: str, element: str,
                 poll_interval: float, timeout_s: float) -> tuple[list[dict], dict]:
    """Wait for COMPLETED, then read every page. Returns (rows, report metadata)."""
    url = f"{base}{REPORT_PATH}/{report_id}"
    deadline = time.monotonic() + timeout_s
    interval = poll_interval
    while True:
        data = check_response(send(session, "GET", url, params={"page": 0}), f"Report {report_id}")
        status = (data.get("_embedded", {}).get("status") or data.get("status") or "").upper()
        if status == "COMPLETED":
            break
        if status and status not in RUNNING_STATES:
            raise RuntimeError(f"Report {report_id} ended with status {status}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"Report {report_id} not completed after {timeout_s:.0f}s (last: {status})")
        log.info("  %s report %s: %s", element, report_id, status or "pending")
        time.sleep(interval)
        interval = min(interval * 1.5, 60)

    embedded = data.get("_embedded", {})
    meta = {k: embedded.get(k) for k in ("data_refresh_date", "date_report_completed")}
    rows = list(embedded.get(element) or [])
    total_pages = _page_count(data)
    page = 1
    while (total_pages is not None and page < total_pages) or (total_pages is None and _has_next_link(data)):
        data = check_response(send(session, "GET", url, params={"page": page}),
                              f"Report {report_id} page {page}")
        batch = data.get("_embedded", {}).get(element) or []
        if not batch:
            if total_pages is not None:  # stopping here would silently drop the remaining pages
                raise RuntimeError(f"Report {report_id} page {page} of {total_pages} came back empty; "
                                   "run again")
            break
        rows.extend(batch)
        page += 1
    log.info("  %s: %d rows in %d page(s)", element, len(rows), page)
    return rows, meta


def fetch_applications(session: requests.Session, base: str) -> list[dict] | None:
    """Full app inventory (Applications API). None when the account lacks access."""
    apps: list[dict] = []
    page = 0
    while True:
        resp = send(session, "GET", base + APPS_PATH, params={"page": page, "size": 500})
        if resp.status_code in (401, 403):
            log.warning("Applications API returned %s; skipping inventory (needs the Results API "
                        "role or Reviewer/Security Lead).", resp.status_code)
            return None
        data = check_response(resp, "List applications")
        apps.extend(data.get("_embedded", {}).get("applications", []))
        total = data.get("page", {}).get("total_pages", 0)
        page += 1
        if page >= total:
            return apps


# --------------------------------------------------------------------------- normalization

def _int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def finding_key(f: dict) -> tuple:
    context = (str(f.get("app_id")), str(f.get("policy_sandbox") or ""), str(f.get("sandbox_id") or ""))
    if f.get("finding_id"):
        return (*context, str(f.get("scan_type")), str(f["finding_id"]))
    return (*context, str(f.get("scan_type")),
            str(f.get("flaw_id")), str(f.get("component_name") or ""), str(f.get("cve_id") or ""))


def dedupe(rows: Iterable[dict], key, order_field: str) -> list[dict]:
    """Keep the most recently updated copy of each object."""
    best: dict[tuple, dict] = {}
    for row in rows:
        k = key(row)
        if k not in best or str(row.get(order_field) or "") >= str(best[k].get(order_field) or ""):
            best[k] = row
    return list(best.values())


def is_open(f: dict) -> bool:
    return str(f.get("status") or "").strip().lower() == "open"


def mitigation_pending(f: dict) -> bool:
    proposed = f.get("mitigation_last_proposed_date")
    if not proposed:
        return False
    decided = max(str(f.get("mitigation_last_accepted_date") or ""),
                  str(f.get("mitigation_last_rejected_date") or ""))
    return str(proposed) > decided


def enrich_finding(f: dict, today: dt.date, window: tuple[dt.date, dt.date] | None = None) -> dict:
    """Add the derived columns in place and return the row (no copy: tenants can have 100k+ rows)."""
    sev = _int(f.get("severity"))
    open_ = is_open(f)
    found = parse_date(f.get("found_date"))
    # A reopened finding can keep its old fixed_date; only closed findings count as fixed.
    fixed = None if open_ else parse_date(f.get("fixed_date"))
    grace = parse_date(f.get("grace_period_expiry_date"))
    f["severity"] = sev
    f["severity_name"] = SEVERITY_NAMES.get(sev, "") if sev is not None else ""
    f["days_open"] = (today - found).days if open_ and found else None
    f["days_to_fix"] = (fixed - found).days if fixed and found and fixed >= found else None
    f["fixed_in_window"] = bool(fixed and (window is None or window[0] <= fixed <= window[1]))
    f["overdue"] = bool(open_ and grace and grace < today
                        and str(f.get("policy_rule_passed") or "").lower() == "no")
    f["mitigation_pending"] = mitigation_pending(f)
    return f


def scan_key(s: dict) -> tuple:
    return (str(s.get("app_id")), str(s.get("scan_id")), str(s.get("analysis_unit_id") or ""))


# --------------------------------------------------------------------------- analysis

PASS_LABELS = {"Passed", "Pass"}
UNASSESSED = {None, "", "Not Assessed", "Calculating", "Determining", "Vendor Review"}
CRITICALITY = {"VERY_HIGH": ("Very High", 2.0), "HIGH": ("High", 1.5), "MEDIUM": ("Medium", 1.0),
               "LOW": ("Low", 0.75), "VERY_LOW": ("Very Low", 0.5)}
SCAN_TYPE_LABELS = {"STATIC": "SAST", "Static Analysis": "SAST", "DYNAMIC": "DAST",
                    "Dynamic Analysis": "DAST", "Dynamic Analysis - Scan Linked": "DAST",
                    "DynamicDS": "DAST", "DynamicMP - Scan Linked": "DAST", "MANUAL": "Manual",
                    "Manual Penetration Testing": "Manual", "Manual Analysis": "Manual", "SCA": "SCA"}
COVERAGE_TYPES = ("SAST", "SCA", "DAST", "Manual")
DEBT_DAYS = 365
AGE_BUCKETS = ((30, "0-30"), (90, "31-90"), (180, "91-180"), (365, "181-365"), (None, "365+"))
# Veracode State of Software Security 2025, leading vs lagging organizations.
BENCH_PREVALENCE = "leaders < 43%, laggards 86%"
BENCH_CAPACITY = "leaders 10%+, laggards ~1%"
BENCH_HALF_LIFE = "leaders ~35 days, laggards 365+"


def compliance_label(value: Any) -> str | None:
    """'DID_NOT_PASS' (Applications API) and 'Did Not Pass' (Reporting API) -> 'Did Not Pass'."""
    return str(value).replace("_", " ").title() if value else None


def is_used(value: Any) -> bool:
    return bool(value) and str(value).strip().lower() not in ("not specified", "none", "")


def latest_policy_scans(scans: list[dict]) -> dict[str, dict]:
    """Most recent policy scan per app (any scan type), by published date, else submitted."""
    latest: dict[str, dict] = {}
    for s in scans:
        if str(s.get("policy_sandbox") or "").lower() != "policy":
            continue
        when = str(s.get("published") or s.get("submitted") or "")
        app = str(s.get("app_id"))
        if when and (app not in latest or when > str(latest[app].get("published") or latest[app].get("submitted") or "")):
            latest[app] = s
    return latest


def is_debt(f: dict) -> bool:
    return f["days_open"] is not None and f["days_open"] > DEBT_DAYS


def build_app_rows(findings: list[dict], scans: list[dict], apps: list[dict] | None,
                   today: dt.date) -> list[dict]:
    rows: dict[str, dict] = {}

    def row_for(app_id: str, name: Any, bu: Any) -> dict:
        r = rows.get(app_id)
        if r is None:
            r = rows[app_id] = {c: None for c in APP_COLUMNS}
            r.update(app_id=app_id, teams="", scan_types=set(), risk_score=0.0)
            for c in COUNT_COLUMNS:
                r[c] = 0
        r["app_name"] = r["app_name"] or name
        r["business_unit"] = r["business_unit"] or (bu if is_used(bu) else None)
        return r

    fix_times: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        r = row_for(str(f.get("app_id")), f.get("app_name"), f.get("business_unit"))
        label = SCAN_TYPE_LABELS.get(str(f.get("scan_type")))
        if label:
            r["scan_types"].add(label)
        if is_open(f):
            r["open"] += 1
            r["open_very_high"] += f["severity"] == 5
            r["open_high"] += f["severity"] == 4
            r["open_policy_violations"] += str(f.get("policy_rule_passed") or "").lower() == "no"
            r["security_debt"] += is_debt(f)
        r["overdue"] += f["overdue"]
        r["mitigations_pending"] += f["mitigation_pending"]
        if f["fixed_in_window"]:
            r["fixed_in_window"] += 1
            if f["days_to_fix"] is not None:
                fix_times[r["app_id"]].append(f["days_to_fix"])

    for s in scans:
        label = SCAN_TYPE_LABELS.get(str(s.get("scan_type")))
        if label:
            row_for(str(s.get("app_id")), s.get("app_name"), s.get("business_unit"))["scan_types"].add(label)
    for app_id, s in latest_policy_scans(scans).items():
        r = row_for(app_id, s.get("app_name"), s.get("business_unit"))
        last = parse_date(s.get("published") or s.get("submitted"))
        r["last_scan"] = last.isoformat() if last else None
        r["days_since_scan"] = (today - last).days if last else None
        r["policy_compliance"] = compliance_label(s.get("scan_policy_compliance"))
        r["veracode_level"] = s.get("veracode_level")

    for app in apps or []:
        profile = app.get("profile") or {}
        r = row_for(str(app.get("id")), profile.get("name"), (profile.get("business_unit") or {}).get("name"))
        r["teams"] = ", ".join(sorted(t.get("team_name") for t in profile.get("teams") or [] if t.get("team_name")))
        crit = CRITICALITY.get(str(profile.get("business_criticality") or "").upper())
        r["business_criticality"] = crit[0] if crit else None
        # The app's current status wins over the last scan's: grace-period expiry, approved
        # mitigations and policy changes move it without a new scan.
        policies = profile.get("policies") or []
        current = compliance_label(policies[0].get("policy_compliance_status")) if policies else None
        r["policy_compliance"] = current or r["policy_compliance"]
        for scan in app.get("scans") or []:
            label = SCAN_TYPE_LABELS.get(str(scan.get("scan_type")))
            if label:
                r["scan_types"].add(label)
        last = parse_date(app.get("last_completed_scan_date"))
        if last and not r["last_scan"]:
            r["last_scan"] = last.isoformat()
            r["days_since_scan"] = (today - last).days

    weights = {v[0]: v[1] for v in CRITICALITY.values()}
    for r in rows.values():
        if r["app_id"] in fix_times:
            r["median_days_to_fix"] = int(statistics.median(fix_times[r["app_id"]]))
        r["risk_score"] = round((10 * r["open_very_high"] + 5 * r["open_high"] + 3 * r["overdue"]
                                 + 2 * r["security_debt"]) * weights.get(r["business_criticality"], 1.0), 1)
        r["scan_types"] = ", ".join(t for t in COVERAGE_TYPES if t in r["scan_types"])
    return sorted(rows.values(), key=lambda r: (-r["risk_score"], -r["open"], str(r["app_name"] or "")))


def month(value: Any) -> str | None:
    d = parse_date(value)
    return d.strftime("%Y-%m") if d else None


def pct(part: float, whole: float) -> str:
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def half_life(findings: list[dict], start: dt.date, today: dt.date) -> int | None:
    """Days until half of the findings first found in the window are closed (Kaplan-Meier).

    Open findings count as still open at their current age, so a slow backlog is not hidden
    the way a median over fixed findings only would hide it.
    """
    events: list[tuple[int, bool]] = []
    for f in findings:
        found = parse_date(f.get("found_date"))
        if not found or found < start:
            continue
        if is_open(f):
            events.append(((today - found).days, False))
        elif f["days_to_fix"] is not None:
            events.append((f["days_to_fix"], True))
    if not events:
        return None
    events.sort()
    at_risk, survival, i = len(events), 1.0, 0
    while i < len(events):
        t, fixed = events[i][0], 0
        j = i
        while j < len(events) and events[j][0] == t:
            fixed += events[j][1]
            j += 1
        if fixed:
            survival *= 1 - fixed / at_risk
            if survival <= 0.5:
                return t
        at_risk -= j - i
        i = j
    return None


def grace_adherence(findings: list[dict], window: tuple[dt.date, dt.date], today: dt.date) -> tuple[int, int]:
    """(met, due): findings whose fix-by date fell in the window, and how many were fixed by then."""
    met = due = 0
    for f in findings:
        grace = parse_date(f.get("grace_period_expiry_date"))
        if not grace or not (window[0] <= grace <= min(window[1], today)):
            continue
        due += 1
        fixed = None if is_open(f) else parse_date(f.get("fixed_date"))
        met += bool(fixed and fixed <= grace)
    return met, due


def months_in(window: tuple[dt.date, dt.date]) -> float:
    return max(((window[1] - window[0]).days + 1) / 30.44, 1.0)


def group_stats(name: str, members: list[dict], findings_by_app: dict[str, list[dict]],
                window: tuple[dt.date, dt.date], stale_days: int) -> list[Any]:
    assessed = [r for r in members if r["policy_compliance"] not in UNASSESSED]
    passing = sum(r["policy_compliance"] in PASS_LABELS for r in assessed)
    scanned = sum(r["days_since_scan"] is not None and r["days_since_scan"] <= stale_days for r in members)
    open_ = sum(r["open"] for r in members)
    fixed = sum(r["fixed_in_window"] for r in members)
    times = [f["days_to_fix"] for r in members for f in findings_by_app.get(r["app_id"], [])
             if f["fixed_in_window"] and f["days_to_fix"] is not None]
    return [name, len(members), pct(passing, len(assessed)), pct(scanned, len(members)),
            sum(r["open_very_high"] for r in members), sum(r["open_high"] for r in members), open_,
            sum(r["overdue"] for r in members), sum(r["security_debt"] for r in members),
            f"{100 * fixed / months_in(window) / (open_ + fixed):.1f}%" if open_ + fixed else "n/a",
            int(statistics.median(times)) if times else ""]


GROUP_HEADERS = ["Apps", "Passing policy", "Scanned in {d} days", "Open VH", "Open H", "Open",
                 "Overdue", "Debt > 1 year", "Fix capacity / month", "Median days to fix"]


# --------------------------------------------------------------------------- markdown

def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    def cell(v: Any) -> str:
        return "" if v is None else " ".join(str(v).splitlines()).replace("|", "\\|")
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(cell(v) for v in r) + " |" for r in rows]
    return "\n".join(out)


def render_markdown(findings: list[dict], scans: list[dict], app_rows: list[dict],
                    window: tuple[dt.date, dt.date], meta: dict, today: dt.date,
                    stale_days: int, top: int, inventory: bool) -> str:
    open_f = [f for f in findings if is_open(f)]
    fixed_w = [f for f in findings if f["fixed_in_window"]]
    n_apps = len(app_rows)
    uses_bu = any(r["business_unit"] for r in app_rows)
    uses_teams = any(r["teams"] for r in app_rows)
    findings_by_app: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        findings_by_app[str(f.get("app_id"))].append(f)

    assessed = [r for r in app_rows if r["policy_compliance"] not in UNASSESSED]
    passing = sum(r["policy_compliance"] in PASS_LABELS for r in assessed)
    scanned_window = {app for app, s in latest_policy_scans(scans).items()}
    prevalence_base = [r for r in app_rows if r["app_id"] in scanned_window]
    with_open = sum(r["open"] > 0 for r in prevalence_base)
    capacity = len(fixed_w) / months_in(window) / (len(open_f) + len(fixed_w)) if (open_f or fixed_w) else 0
    hl = half_life(findings, window[0], today)
    met, due = grace_adherence(findings, window, today)
    debt = [f for f in open_f if is_debt(f)]
    critical_debt = [f for f in debt if (f["severity"] or 0) >= 4]
    sca_critical = sum(f.get("scan_type") == "SCA" for f in critical_debt)
    recent = sum(r["days_since_scan"] is not None and r["days_since_scan"] <= stale_days for r in app_rows)
    open_vh_h = sum((f["severity"] or 0) >= 4 for f in open_f)

    out: list[str] = [
        "# Veracode portfolio review", "",
        (f"Window: **{window[0]} to {window[1]}**, policy findings and scans updated in this period. "
         f"Data refreshed: {str(meta.get('data_refresh_date') or 'n/a')[:16]}."), "",
        "## Scorecard", "",
        md_table(["Measure", "Value", "Benchmark"], [
            ["Applications", n_apps, ""],
            ["Passing policy", f"{pct(passing, len(assessed))} ({passing} of {len(assessed)} assessed)", ""],
            [f"Scanned in the last {stale_days} days", f"{pct(recent, n_apps)} ({recent} of {n_apps})", ""],
            ["Flaw prevalence (apps with open flaws)",
             f"{pct(with_open, len(prevalence_base))} ({with_open} of {len(prevalence_base)} scanned in window)",
             BENCH_PREVALENCE],
            ["Fix capacity (share of flaws fixed per month)", f"{100 * capacity:.1f}%", BENCH_CAPACITY],
            ["Fix speed (half-life of new flaws)", f"{hl} days" if hl is not None else "not reached in window",
             BENCH_HALF_LIFE],
            ["Fixed by the policy fix-by date", f"{pct(met, due)} ({met} of {due} due in window)", ""],
            ["Open Very High / High", open_vh_h, ""],
            ["Overdue (open past fix-by date)", sum(f["overdue"] for f in findings), ""],
            ["Security debt (open > 1 year)",
             f"{len(debt)} findings in {len({f.get('app_id') for f in debt})} apps", ""],
            ["Critical debt (Very High / High, open > 1 year)",
             f"{len(critical_debt)} ({pct(sca_critical, len(critical_debt))} from open-source libraries)", ""],
            ["Mitigations awaiting a decision", sum(f["mitigation_pending"] for f in findings), ""],
        ]), "",
        "> [!NOTE]",
        ("> Benchmarks are from Veracode's State of Software Security 2025. The Reporting API only "
         "returns findings updated in the last six months, so open and debt counts are complete for "
         "apps scanned in the window and a minimum for the rest. Use the Findings API export for the "
         "full backlog."), "",
    ]

    takeaways = []
    worst = [r for r in app_rows if r["risk_score"] > 0][:3]
    if worst:
        takeaways.append("Highest-risk applications: " + ", ".join(
            f"**{r['app_name']}** ({r['open_very_high']} VH, {r['open_high']} H, {r['overdue']} overdue)" for r in worst) + ".")
    if open_f or fixed_w:
        verdict = "leading" if capacity >= 0.10 else "lagging" if capacity <= 0.01 else "between leading and lagging"
        takeaways.append(f"Fix capacity of {100 * capacity:.1f}% a month is {verdict} by the SoSS 2025 benchmark.")
    if due:
        takeaways.append(f"{due - met} of {due} findings due in the window missed their policy fix-by date.")
    if n_apps - recent:
        crit_stale = sum(r["business_criticality"] in ("Very High", "High") and not
                         (r["days_since_scan"] is not None and r["days_since_scan"] <= stale_days) for r in app_rows)
        takeaways.append(f"{n_apps - recent} applications have no scan in {stale_days} days"
                         + (f", {crit_stale} of them high business criticality." if crit_stale else "."))
    if critical_debt:
        takeaways.append(f"{len(critical_debt)} Very High/High findings have been open over a year; "
                         f"{pct(sca_critical, len(critical_debt))} are in open-source libraries.")
    if takeaways:
        out += ["## Key takeaways", ""] + [f"- {t}" for t in takeaways] + [""]

    dated = [month(f.get(k)) for f in findings for k in ("found_date", "fixed_date")]
    dated += [month(s.get("published") or s.get("submitted")) for s in scans]
    months = sorted({m for m in dated if m and m >= window[0].strftime("%Y-%m")})
    found_m = Counter(month(f.get("found_date")) for f in findings)
    fixed_m = Counter(month(f.get("fixed_date")) for f in fixed_w)
    scans_m = Counter(month(s.get("published") or s.get("submitted")) for s in scans)
    apps_m: dict[str, set] = defaultdict(set)
    for s in scans:
        apps_m[month(s.get("published") or s.get("submitted"))].add(s.get("app_id"))
    out += ["## Trend by month", "",
            md_table(["Month", "New flaws", "Fixed", "Net change", "Fix ratio", "Scans", "Apps scanned"],
                     [[m, found_m[m], fixed_m[m], f"{found_m[m] - fixed_m[m]:+d}",
                       f"{fixed_m[m] / found_m[m]:.2f}" if found_m[m] else "", scans_m[m], len(apps_m[m])]
                      for m in months]),
            "", "Fix ratio above 1.00 means the backlog shrank that month.", ""]

    out += ["## Open flaws by severity and age", ""]
    rows = []
    for sev in (5, 4, 3, 2, 1, 0):
        ages = [f["days_open"] for f in open_f if f["severity"] == sev and f["days_open"] is not None]
        times = sorted(f["days_to_fix"] for f in fixed_w if f["severity"] == sev and f["days_to_fix"] is not None)
        buckets = Counter()
        for a in ages:
            buckets[next(label for limit, label in AGE_BUCKETS if limit is None or a <= limit)] += 1
        rows.append([SEVERITY_NAMES[sev], sum(f["severity"] == sev for f in open_f)]
                    + [buckets[label] for _, label in AGE_BUCKETS]
                    + [int(statistics.median(times)) if times else "",
                       times[math.ceil(0.9 * len(times)) - 1] if times else ""])
    out += [md_table(["Severity", "Open"] + [f"{label} days" for _, label in AGE_BUCKETS]
                     + ["Median days to fix", "P90 days to fix"], rows), ""]

    risky = [r for r in app_rows if r["risk_score"] > 0][:top]
    headers = ["Application"] + (["Business unit"] if uses_bu else []) + (["Teams"] if uses_teams else []) + [
        "Criticality", "Risk score", "Open VH", "Open H", "Overdue", "Debt > 1 year", "Last scan", "Policy"]
    out += ["## Applications needing attention", "",
            md_table(headers, [[r["app_name"]] + ([r["business_unit"] or ""] if uses_bu else [])
                               + ([r["teams"]] if uses_teams else [])
                               + [r["business_criticality"] or "", r["risk_score"], r["open_very_high"],
                                  r["open_high"], r["overdue"], r["security_debt"], r["last_scan"] or "",
                                  r["policy_compliance"] or ""] for r in risky]) if risky else "None.",
            "", ("Risk score = (10 x open Very High + 5 x open High + 3 x overdue + 2 x debt) "
                 "x business criticality weight (Very High 2, High 1.5, Medium 1, Low 0.75, Very Low 0.5)."), ""]

    group_headers = [h.format(d=stale_days) for h in GROUP_HEADERS]
    if uses_bu:
        by_bu: dict[str, list[dict]] = defaultdict(list)
        for r in app_rows:
            by_bu[r["business_unit"] or "Not Specified"].append(r)
        out += ["## Business units", "",
                md_table(["Business unit"] + group_headers,
                         sorted((group_stats(k, v, findings_by_app, window, stale_days) for k, v in by_bu.items()),
                                key=lambda g: (-g[4], -g[5], g[0]))), ""]
    if uses_teams:
        by_team: dict[str, list[dict]] = defaultdict(list)
        for r in app_rows:
            for team in (r["teams"].split(", ") if r["teams"] else ["No team"]):
                by_team[team].append(r)
        out += ["## Teams", "",
                md_table(["Team"] + group_headers,
                         sorted((group_stats(k, v, findings_by_app, window, stale_days) for k, v in by_team.items()),
                                key=lambda g: (-g[4], -g[5], g[0]))),
                "", "Applications in several teams count in each.", ""]

    out += ["## Scan coverage", ""]
    cov_rows = [[t, sum(t in r["scan_types"] for r in app_rows),
                 pct(sum(t in r["scan_types"] for r in app_rows), n_apps)] for t in COVERAGE_TYPES]
    out += [md_table(["Scan type", "Apps", "Share of portfolio"], cov_rows), ""]
    by_crit: dict[str, list[dict]] = defaultdict(list)
    for r in app_rows:
        by_crit[r["business_criticality"] or "Not set"].append(r)
    if inventory and any(k != "Not set" for k in by_crit):
        order = [v[0] for v in CRITICALITY.values()] + ["Not set"]
        out += [md_table(["Business criticality", "Apps", f"Scanned in {stale_days} days", "Passing policy",
                          "Open VH", "Open H"],
                         [[k, len(v), pct(sum(r["days_since_scan"] is not None and r["days_since_scan"] <= stale_days
                                              for r in v), len(v)),
                           pct(sum(r["policy_compliance"] in PASS_LABELS for r in v),
                               sum(r["policy_compliance"] not in UNASSESSED for r in v)),
                           sum(r["open_very_high"] for r in v), sum(r["open_high"] for r in v)]
                          for k in order if (v := by_crit.get(k))]), ""]
    stale = sorted((r for r in app_rows if r["days_since_scan"] is None or r["days_since_scan"] > stale_days),
                   key=lambda r: (-(r["days_since_scan"] or 10**6), str(r["app_name"])))
    out += [f"Applications with no scan in the last {stale_days} days: **{len(stale)}**.", ""]
    if stale:
        out += [md_table(["Application", "Criticality", "Last scan", "Days ago", "Policy"],
                         [[r["app_name"], r["business_criticality"] or "", r["last_scan"] or "never",
                           r["days_since_scan"] if r["days_since_scan"] is not None else "",
                           r["policy_compliance"] or ""] for r in stale[:top]]), ""]
    if not inventory:
        out += ["> [!NOTE]", ("> Application inventory was skipped, so apps with no activity in the window, "
                              "teams and business criticality are not shown. Give the account the Results API "
                              "role to include them."), ""]

    overdue = sorted((f for f in findings if f["overdue"]),
                     key=lambda f: (-(f["severity"] or 0), str(f.get("grace_period_expiry_date"))))
    out += [f"## Overdue findings ({len(overdue)})", ""]
    out += [md_table(["Application", "Severity", "CWE", "Flaw / component", "Fix by", "Days overdue", "Scan type"],
                     [[f.get("app_name"), f["severity_name"], f.get("cwe_id"),
                       f.get("flaw_name") or f.get("component_name"), str(f.get("grace_period_expiry_date"))[:10],
                       (today - parse_date(f.get("grace_period_expiry_date"))).days, f.get("scan_type")]
                      for f in overdue[:top]]) if overdue else "None.", ""]

    cwe = Counter((f.get("cwe_id"), f.get("category_name") or f.get("flaw_name")) for f in open_f
                  if f.get("cwe_id") and f.get("scan_type") != "SCA")
    if cwe:
        out += ["## Most common open weaknesses (first-party code)", "",
                md_table(["CWE", "Name", "Open", "Apps"],
                         [[c[0], c[1], n, len({f.get("app_id") for f in open_f
                                              if (f.get("cwe_id"), f.get("category_name") or f.get("flaw_name")) == c})]
                          for c, n in cwe.most_common(top)]), ""]

    sca = Counter((f.get("component_name"), f.get("component_version"),
                   f.get("fixed_library_version") or f.get("library_latest_safe_version"))
                  for f in open_f if f.get("scan_type") == "SCA" and f.get("component_name"))
    if sca:
        sca_open = [f for f in open_f if f.get("scan_type") == "SCA"]
        upgradable = sum(bool(f.get("fixed_library_version") or f.get("library_latest_safe_version")) for f in sca_open)
        out += ["## Open-source risk", "",
                (f"{len(sca_open)} open findings in third-party libraries; {pct(upgradable, len(sca_open))} "
                 "have a fixed or safe version to upgrade to."), "",
                md_table(["Library", "Version", "Upgrade to", "Open", "Apps"],
                         [[c[0], c[1], c[2] or "", n,
                           len({f.get("app_id") for f in sca_open if f.get("component_name") == c[0]
                                and f.get("component_version") == c[1]})]
                          for c, n in sca.most_common(top)]), ""]

    in_window = lambda v: (d := parse_date(v)) is not None and window[0] <= d <= window[1]
    accepted = sum(in_window(f.get("mitigation_last_accepted_date")) for f in findings)
    rejected = sum(in_window(f.get("mitigation_last_rejected_date")) for f in findings)
    out += ["## Mitigations", "",
            md_table(["Measure", "Findings"], [
                ["Awaiting a decision", sum(f["mitigation_pending"] for f in findings)],
                ["Accepted in window", accepted],
                ["Rejected in window", rejected],
            ]), ""]
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- output

def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)


def write_json(path: Path, data: Any) -> None:
    """Stream to disk: a 100k-row report would otherwise be built as one huge string first."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=1)
    tmp.replace(path)


# --------------------------------------------------------------------------- main

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Veracode portfolio review via the Reporting API.")
    p.add_argument("--start-date", help="YYYY-MM-DD, at most six months ago (default: six months ago).")
    p.add_argument("--end-date", help="YYYY-MM-DD, inclusive (default: today).")
    p.add_argument("--output-dir", default="portfolio_report", help="Output folder (default: portfolio_report).")
    p.add_argument("--include-sandbox", action="store_true", help="Include sandbox findings and scans.")
    p.add_argument("--stale-days", type=int, default=90, help="Flag apps with no scan in N days (default: 90).")
    p.add_argument("--top", type=int, default=20, help="Rows per ranked table (default: 20).")
    p.add_argument("--no-inventory", action="store_true", help="Skip the Applications API inventory call.")
    p.add_argument("--raw-json", action="store_true", help="Also save the raw report rows.")
    p.add_argument("--poll-interval", type=float, default=10, help="Initial seconds between status checks (default: 10).")
    p.add_argument("--timeout", type=float, default=60, help="Minutes to wait per report (default: 60).")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    load_credentials_env()
    today = dt.date.today()
    start, end = resolve_window(args.start_date, args.end_date, today)
    base = api_base()
    session = create_session()

    common: dict[str, Any] = {
        "last_updated_start_date": f"{start} 00:00:00",
        # The end bound is exclusive at 00:00:00, so the next day covers all of end_date.
        "last_updated_end_date": f"{end + dt.timedelta(days=1)} 00:00:00",
    }
    if not args.include_sandbox:
        common["policy_sandbox"] = "Policy"

    log.info("Window %s to %s on %s", start, end, base)
    ids = {
        "findings": request_report(session, base, {"report_type": "FINDINGS", **common}),
        "scans": request_report(session, base, {"report_type": "SCANS", **common}),
    }
    raw_findings, meta = fetch_report(session, base, ids["findings"], "findings",
                                      args.poll_interval, args.timeout * 60)
    raw_scans, _ = fetch_report(session, base, ids["scans"], "scans", args.poll_interval, args.timeout * 60)
    apps = None if args.no_inventory else fetch_applications(session, base)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if args.raw_json:  # before enrichment, which adds columns to the rows in place
        write_json(out / "raw_findings.json", raw_findings)
        write_json(out / "raw_scans.json", raw_scans)

    raw_count = len(raw_findings)
    findings = [enrich_finding(f, today, (start, end))
                for f in dedupe(raw_findings, finding_key, "last_updated_date")]
    del raw_findings
    findings.sort(key=lambda f: (str(f.get("app_name")), -(f["severity"] or 0), str(f.get("finding_id"))))
    scans = dedupe(raw_scans, scan_key, "last_updated_date")
    scans.sort(key=lambda s: (str(s.get("app_name")), str(s.get("published") or s.get("submitted"))))
    app_rows = build_app_rows(findings, scans, apps, today)
    log.info("Findings %d (%d duplicates removed), scans %d, apps %d",
             len(findings), raw_count - len(findings), len(scans), len(app_rows))

    # Drop grouping columns the tenant does not use (no business units, teams or criticality set).
    unused = {c for c in ("business_unit", "teams", "business_criticality")
              if not any(r[c] for r in app_rows)}
    write_csv(out / "findings.csv", findings, [c for c in FINDING_COLUMNS if c not in unused])
    write_csv(out / "scans.csv", scans, [c for c in SCAN_COLUMNS if c not in unused])
    write_csv(out / "applications.csv", app_rows, [c for c in APP_COLUMNS if c not in unused])
    write_text(out / "PORTFOLIO.md", render_markdown(
        findings, scans, app_rows, (start, end), meta, today, args.stale_days, args.top, apps is not None))
    log.info("Wrote %s", out.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
