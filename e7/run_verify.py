#!/usr/bin/env python3
"""E7 verify step (REG-53): turn today's config-ok candidates into a usable-node count.

Runs on the GitHub Actions runner, after e7/run_round.py. For each candidate
in e7-results/<date>.json it performs the full chain, reusing upstream
wzdnzd/aggregator code (Apache-2.0):

    register (Emailnator temporary gmail) -> free-plan check
    -> fetch subscription -> count node URIs -> TCP-probe host:port

Output: e7-results/<date>-verify.json with ONLY safe fields
(domain, booleans, counts, reason). NEVER writes: email addresses,
passwords, cookies, auth tokens, subscription URLs, or node URIs.
Same-date runs accumulate: sites already verified with a terminal
outcome are kept; transient failures (register_failed, sub_fetch_empty,
error:*) are retried. The file also carries an "emailnator_diag" entry:
a plain GET to https://www.emailnator.com from the runner, so a dead
mail path can be told apart from a dead airport panel.
Public-repo rule: the runner log is public, so this script prints no
credentials either (upstream error logs may include a one-time 6-digit
verification code for a throwaway temp account if mask extraction fails;
that code is single-use and expires within minutes).

"Usable node" here means: the node endpoint accepted a TCP connection
within 3s. It is a liveness proxy, not a full Mihomo protocol check.
"""
import base64
import concurrent.futures
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "subscribe"))
os.chdir(REPO)

import airport  # noqa: E402
import renewal  # noqa: E402
import utils  # noqa: E402

logging.getLogger().setLevel(logging.INFO)

SCHEMES = (
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "snell://",
    "naive://",
    "socks://",
)

HOSTPORT_RE = re.compile(r"://(?:[^@/]+@)?([^:/?#\[\]]+|\[[^\]]+\]):(\d+)")


def _decode_maybe_b64(text: str) -> str:
    """Subscription bodies are often a single base64 blob; decode it."""
    stripped = text.strip()
    if "://" in stripped:
        return text
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        return decoded if "://" in decoded else text
    except Exception:
        return text


def parse_nodes(text: str) -> list[str]:
    text = _decode_maybe_b64(text)
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(SCHEMES):
            nodes.append(line)
    return nodes


def parse_hostport(uri: str):
    """Return (host, port) or None. Never logs the uri itself."""
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://"):]
            padded = payload + "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            return str(data["add"]).strip("[]"), int(data["port"])
        m = HOSTPORT_RE.search(uri)
        if not m:
            return None
        return m.group(1).strip("[]"), int(m.group(2))
    except Exception:
        return None


def tcp_probe(hostport, timeout: float = 3.0) -> bool:
    host, port = hostport
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def probe_nodes(uris: list[str]) -> int:
    targets = []
    for uri in uris:
        hp = parse_hostport(uri)
        if hp and 0 < hp[1] < 65536:
            targets.append(hp)
    if not targets:
        return 0
    reachable = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for ok in ex.map(tcp_probe, targets):
            reachable += 1 if ok else 0
    return reachable


RETRY_REASONS = {"register_failed", "sub_fetch_empty"}


def diag_emailnator() -> dict:
    """Runner-side reachability check for the mail path. No account is
    created here; plain GET, status + header inspection only.
    Distinguishes 'mail path dead' from 'airport panel dead'."""
    diag = {"reachable": False, "status": None, "error": None,
            "set_cookie_count": 0, "xsrf_in_headers": False,
            "challenge_markers": []}
    try:
        req = urllib.request.Request(
            url="https://www.emailnator.com",
            headers={"User-Agent": utils.USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=10, context=utils.CTX) as resp:
            diag["status"] = resp.getcode()
            diag["reachable"] = resp.getcode() == 200
            try:
                raw_cookies = resp.headers.get_all("Set-Cookie") or []
            except Exception:
                raw_cookies = []
            diag["set_cookie_count"] = len(raw_cookies)
            joined = "; ".join(raw_cookies)
            diag["xsrf_in_headers"] = "XSRF-TOKEN=" in joined
            try:
                body = resp.read(4096).decode("utf-8", errors="ignore").lower()
            except Exception:
                body = ""
            for marker in ("challenge", "just a moment", "cf-chl", "turnstile",
                           "captcha", "checking your browser"):
                if marker in body:
                    diag["challenge_markers"].append(marker)
    except urllib.error.HTTPError as e:
        diag["status"] = e.code
        diag["error"] = f"HTTPError:{e.code}"
    except Exception as e:
        diag["error"] = type(e).__name__
    return diag


def verify_one(domain: str) -> dict:
    """Verify one candidate. Returns only safe fields."""
    started = time.time()
    rec = {
        "domain": domain,
        "registered": False,
        "free_plan": None,
        "sub_present": False,
        "nodes_total": 0,
        "nodes_reachable": 0,
        "reason": "",
    }
    try:
        ap = airport.AirPort(name=domain, site=domain)
        cookies, auth = ap.get_subscribe(retry=2, allow_gmail_alias=True)
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
            plan = renewal.get_free_plan(
                domain=ap.ref, cookies=cookies, authorization=auth,
                retry=2, api_prefix=ap.api_prefix,
            )
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
    date = sys.argv[1] if len(sys.argv) > 1 else time.strftime("%Y-%m-%d", time.gmtime())
    src_path = os.path.join(REPO, "e7-results", f"{date}.json")
    out_path = os.path.join(REPO, "e7-results", f"{date}-verify.json")
    diag = diag_emailnator()
    print(f"verify: emailnator diag reachable={diag['reachable']} status={diag['status']} error={diag['error']} "
          f"set_cookie={diag['set_cookie_count']} xsrf={diag['xsrf_in_headers']} challenge={diag['challenge_markers']}")
    old_sites = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                old_sites = {s["domain"]: s for s in json.load(f).get("sites", [])}
        except Exception:
            old_sites = {}
    if not os.path.exists(src_path):
        print(f"verify: no results file {src_path}, nothing to verify")
        result = {"date": date, "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "total_candidates": 0, "usable_nodes": 0, "emailnator_diag": diag, "sites": []}
    else:
        with open(src_path, encoding="utf-8") as f:
            src = json.load(f)
        candidates = src.get("candidates", []) or []
        to_verify = [c for c in candidates
                     if c not in old_sites
                     or old_sites[c].get("reason") in RETRY_REASONS
                     or str(old_sites[c].get("reason", "")).startswith("error:")]
        print(f"verify: {len(candidates)} candidates from {date}, "
              f"{len(to_verify)} to verify ({len(old_sites)} already on file)")
        new_sites = [verify_one(c) for c in to_verify]
        merged = dict(old_sites)
        for s in new_sites:
            merged[s["domain"]] = s
        sites = [merged[d] for d in list(dict.fromkeys(
            list(old_sites.keys()) + [s["domain"] for s in new_sites]))]
        usable = sum(s["nodes_reachable"] for s in sites)
        result = {"date": date, "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "total_candidates": len(candidates), "usable_nodes": usable,
                  "emailnator_diag": diag, "sites": sites}
        for s in sites:
            print(f"verify: {s['domain']} registered={s['registered']} free_plan={s['free_plan']} "
                  f"nodes={s['nodes_total']} reachable={s['nodes_reachable']} reason={s['reason']}")
        print(f"verify done: {len(candidates)} candidates, {usable} usable nodes")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"verify: wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
