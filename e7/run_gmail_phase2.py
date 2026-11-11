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
import string
import sys
import time
import urllib.parse
import urllib.request
from copy import deepcopy

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E7 = os.path.join(REPO, "e7")
sys.path.insert(0, E7)
sys.path.insert(0, os.path.join(REPO, "subscribe"))
os.chdir(REPO)

import renewal  # noqa: E402
import utils  # noqa: E402
from airport import ANOTHER_API_PREFIX, AirPort  # noqa: E402
from run_verify import parse_nodes, probe_nodes  # noqa: E402

logging.getLogger().setLevel(logging.INFO)


def to_ascii_site(domain: str) -> str:
    """IDNA-encode a non-ASCII host (e.g. 便宜机场.co) so urllib can use it.
    The record domain stays as-is; only the request URL is punycoded."""
    try:
        parts = urllib.parse.urlsplit(domain)
        host = parts.hostname or ""
        if any(ord(c) > 127 for c in host):
            ascii_host = host.encode("idna").decode("ascii")
            netloc = ascii_host
            if parts.port:
                netloc += f":{parts.port}"
            return urllib.parse.urlunsplit(
                (parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return domain


def canary(ap: AirPort, alias: str, code: str | None) -> str:
    """Deliberately failing POST to the register endpoint. Never creates
    an account (wrong code / invalid email are rejected by validation);
    it only reveals the endpoint's raw response. Alias and password are
    redacted from the log."""
    if code is not None:
        email = f"{alias.split('@')[0]}+diag{secrets.token_hex(2)}@{alias.split('@')[1]}"
        email_code = "000000"
    else:
        email = "not-an-email"
        email_code = ""
    params = {"email": email, "password": "DiagPass1234!x",
              "invite_code": "", "email_code": email_code}
    data = urllib.parse.urlencode(params).encode(encoding="UTF8")
    headers = deepcopy(ap.headers)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    if ap.api_prefix == ANOTHER_API_PREFIX:
        headers["Content-Type"] = "application/json"
        data = json.dumps(params).encode(encoding="UTF8")
    try:
        request = urllib.request.Request(ap.reg, data=data, headers=headers, method="POST")
        response = urllib.request.urlopen(request, timeout=10, context=utils.CTX)
        body = response.read().decode("utf-8", "replace")[:200]
        body = body.replace(email, "<email>").replace("DiagPass1234!x", "<pass>")
        return f"http_{response.getcode()}:{body}"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            body = ""
        body = body.replace(email, "<email>").replace("DiagPass1234!x", "<pass>")
        return f"http_{e.code}:{body}"
    except Exception as e:
        return f"exc:{type(e).__name__}:{str(e)[:150]}"


def make_password() -> str:
    """Panel-safe password: 12 chars, letters+digits only. The upstream
    generator uses string.punctuation (incl. & = + % " ' \\) and some
    panels reject those with a 422; this rules that cause out."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def verbose_register(ap: AirPort, alias: str, password: str,
                     code: str | None) -> tuple[str, str]:
    """Same steps as AirPort.register, but logs the real outcome at each
    point (status / panel message / data keys). Password, alias and code
    are redacted from every logged value."""
    params = {"email": alias, "password": password,
              "invite_code": "", "email_code": utils.trim(code)}
    data = urllib.parse.urlencode(params).encode(encoding="UTF8")
    headers = deepcopy(ap.headers)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    if ap.api_prefix == ANOTHER_API_PREFIX:
        headers["Content-Type"] = "application/json"
        data = json.dumps(params).encode(encoding="UTF8")
    for attempt in range(3):
        try:
            request = urllib.request.Request(ap.reg, data=data, headers=headers, method="POST")
            response = urllib.request.urlopen(request, timeout=10, context=utils.CTX)
            status = response.getcode()
            if status != 200:
                print(f"gmail phase2 register: {ap.ref} http_{status}", flush=True)
                return "", ""
            cookies = utils.extract_cookie(response.getheader("Set-Cookie"))
            payload = json.loads(response.read()).get("data", {})
            if not isinstance(payload, dict):
                print(f"gmail phase2 register: {ap.ref} data_not_dict", flush=True)
                return "", ""
            print(f"gmail phase2 register: {ap.ref} http_200 data_keys={sorted(payload.keys())}",
                  flush=True)
            auth_data = payload.get("auth_data")
            if isinstance(auth_data, dict):
                print(f"gmail phase2 register: {ap.ref} auth_data_keys={sorted(auth_data.keys())}",
                      flush=True)
            else:
                print(f"gmail phase2 register: {ap.ref} auth_data_type={type(auth_data).__name__}"
                      + (f" len={len(auth_data)}" if isinstance(auth_data, str) else ""),
                      flush=True)
            token = payload.get("token", "")
            authorization = payload.get("auth", "")
            if not authorization and isinstance(auth_data, dict):
                # Some panels return the session token inside auth_data.
                authorization = auth_data.get("auth", "") or auth_data.get("token", "")
            if not authorization and isinstance(auth_data, str) and auth_data:
                # This panel family returns the session token as a plain
                # string in auth_data (no "auth" field, no Set-Cookie).
                authorization = auth_data
            ap.username = alias
            ap.password = password
            ap.order_plan(email=alias, password=password, cookies=cookies,
                          authorization=authorization)
            subscribe_info = renewal.get_subscribe_info(
                domain=ap.ref, cookies=cookies, authorization=authorization,
                api_prefix=ap.api_prefix)
            if subscribe_info:
                ap.nodes.subscribe = subscribe_info.sub_url
            if not ap.nodes.subscribe_list():
                if token:
                    ap.nodes.subscribe = f"{ap.ref}/api/v1/client/subscribe?token=<redacted>"
                else:
                    print(f"gmail phase2 register: {ap.ref} no_token_no_sub", flush=True)
            return cookies, authorization
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "replace")[:200]
            except Exception:
                body = ""
            for secret in (alias, password, code or ""):
                if secret:
                    body = body.replace(secret, "<redacted>")
            print(f"gmail phase2 register: {ap.ref} http_{e.code}:{body}", flush=True)
        except Exception as e:
            print(f"gmail phase2 register: {ap.ref} exc:{type(e).__name__}:{str(e)[:120]}",
                  flush=True)
        time.sleep(1)
    print(f"gmail phase2 register: {ap.ref} max_retry", flush=True)
    return "", ""


def verify_site(domain: str, alias: str, code: str | None) -> dict:
    started = time.time()
    rec = {"domain": domain, "mail": "gmail", "registered": False,
           "free_plan": None, "sub_present": False, "nodes_total": 0,
           "nodes_reachable": 0, "reason": ""}
    try:
        ap = AirPort(name=domain, site=to_ascii_site(domain))
        rr = AirPort.get_register_require(domain, default=False)
        ap.api_prefix = rr.api_prefix or ap.api_prefix
        print(f"gmail phase2 canary: {domain} {canary(ap, alias, code)}", flush=True)
        cookies, auth = verbose_register(ap, alias, make_password(), code)
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
        alias = f"{local}@gmail.com" if tag == "bare" else f"{local}+{tag}@gmail.com"
        jobs.append((site, alias, str(code).strip()))
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
