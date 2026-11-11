#!/usr/bin/env python3
"""E7 Gmail phase 2 (REG-53): register with the codes sent in phase 1,
plus direct registration for today's no-verify candidates.

Inputs (env, from workflow_dispatch -- never logged or stored):
- GMAIL_USER: plain @gmail.com address (same as phase 1).
- CODES_JSON: JSON object {site: code} with single-use verification
  codes. Codes are consumed immediately and never written to any file.

Alias reconstruction: pending file holds {site, tag}; alias is
local-part + "+" + tag + "@gmail.com". No email address is stored in
this repo.

Sites processed:
(a) every site in CODES_JSON (code path),
(b) today's config_ok candidates with verify=False (no-code path --
    these need no verification email at all).

Each registered site is checked the same way as run_verify.py:
free plan -> fetch subscription -> count node URIs -> TCP-probe
host:port. Results merge into e7-results/<date>-verify.json with
mail="gmail" marking the path. Only safe fields are written
(domain, booleans, counts, reason); never email, password, cookie,
auth token, subscription URL, or node URI.
"""
import json
import logging
import os
import secrets
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E7 = os.path.join(REPO, "e7")
sys.path.insert(0, E7)
sys.path.insert(0, os.path.join(REPO, "subscribe"))
os.chdir(REPO)

import renewal  # noqa: E402
import utils  # noqa: E402
from airport import AirPort  # noqa: E402
from run_verify import parse_nodes, probe_nodes  # noqa: E402

logging.getLogger().setLevel(logging.INFO)


def verify_site(domain: str, alias: str, code: str | None) -> dict:
    started = time.time()
    rec = {"domain": domain, "mail": "gmail", "registered": False,
           "free_plan": None, "sub_present": False, "nodes_total": 0,
           "nodes_reachable": 0, "reason": ""}
    try:
        ap = AirPort(name=domain, site=domain)
        rr = AirPort.get_register_require(domain, default=False)
        ap.api_prefix = rr.api_prefix or ap.api_prefix
        cookies, auth = ap.register(email=alias, password=None,
                                    email_code=code, retry=2)
        subs = []
        try:
            subs = ap.nodes.subscribe_list() or []
        except Exception:
            subs = []
        rec["sub_present"] = bool(subs)
        rec["registered"] = bool(cookies or auth or subs)
        if not rec["registered"]:
            rec["reason"] = "register_failed"
            return rec
        try:
            plan = renewal.get_free_plan(domain=ap.ref, cookies=cookies,
                                         authorization=auth, retry=2,
                                         api_prefix=ap.api_prefix)
            rec["free_plan"] = plan is not None
        except Exception:
            rec["free_plan"] = None
        if not subs:
            rec["reason"] = "no_subscribe_url"
            return rec
        content = ""
        try:
            content = utils.http_get(url=subs[0], retry=2, timeout=30) or ""
        except Exception:
            content = ""
        if not content.strip():
            rec["reason"] = "sub_fetch_empty"
            return rec
        uris = parse_nodes(content)
        rec["nodes_total"] = len(uris)
        if not uris:
            rec["reason"] = "no_nodes_in_sub"
            return rec
        rec["nodes_reachable"] = probe_nodes(uris)
        rec["reason"] = "ok" if rec["nodes_reachable"] > 0 else "nodes_all_dead"
    except Exception as e:
        rec["reason"] = f"error:{type(e).__name__}"
    finally:
        rec["duration_s"] = round(time.time() - started, 1)
    return rec


def main() -> int:
    gmail_user = os.environ.get("GMAIL_USER", "").strip()
    if not gmail_user.endswith("@gmail.com") or "+" in gmail_user.split("@")[0]:
        print("gmail phase2: GMAIL_USER must be a plain @gmail.com address")
        return 2
    local = gmail_user.split("@")[0]
    try:
        codes = json.loads(os.environ.get("CODES_JSON", "{}") or "{}")
    except Exception:
        codes = {}
    if not isinstance(codes, dict):
        codes = {}
    date = time.strftime("%Y-%m-%d", time.gmtime())
    pending_path = os.path.join(REPO, "e7-results", f"{date}-gmail-pending.json")
    tags = {}
    if os.path.exists(pending_path):
        try:
            with open(pending_path, encoding="utf-8") as f:
                tags = {p["site"]: p["tag"] for p in json.load(f).get("pending", [])}
        except Exception:
            tags = {}
    src_path = os.path.join(REPO, "e7-results", f"{date}.json")
    records = {}
    if os.path.exists(src_path):
        with open(src_path, encoding="utf-8") as f:
            src = json.load(f)
        records = {r["domain"]: r for r in src.get("records", [])}
    jobs = []  # (domain, alias, code or None)
    for site, code in codes.items():
        tag = tags.get(site)
        if not tag:
            print(f"gmail phase2: {site} has no pending tag, skipped")
            continue
        jobs.append((site, f"{local}+{tag}@gmail.com", str(code).strip()))
    for domain, rec in records.items():
        if rec.get("config_ok") and rec.get("verify") is False:
            tag = secrets.token_hex(4)
            jobs.append((domain, f"{local}+{tag}@gmail.com", None))
    print(f"gmail phase2: {len(jobs)} sites ({len(codes)} with code, "
          f"{len(jobs) - len(codes)} no-code)")
    results = {}
    for domain, alias, code in jobs:
        r = verify_site(domain, alias, code)
        results[domain] = r
        print(f"gmail phase2: {domain} registered={r['registered']} "
              f"free_plan={r['free_plan']} nodes={r['nodes_total']} "
              f"reachable={r['nodes_reachable']} reason={r['reason']}")
    out_path = os.path.join(REPO, "e7-results", f"{date}-verify.json")
    old_sites = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                old_sites = {s["domain"]: s for s in json.load(f).get("sites", [])}
        except Exception:
            old_sites = {}
    merged = dict(old_sites)
    merged.update(results)
    sites = list(merged.values())
    usable = sum(s["nodes_reachable"] for s in sites)
    diag = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                diag = json.load(f).get("emailnator_diag", {}) or {}
        except Exception:
            diag = {}
    total_candidates = len([d for d in records.values() if d.get("config_ok")])
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"date": date,
                   "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "total_candidates": total_candidates,
                   "usable_nodes": usable, "emailnator_diag": diag,
                   "sites": sites}, f, ensure_ascii=False, indent=2)
    print(f"gmail phase2 done: {len(jobs)} sites, {usable} usable nodes total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
