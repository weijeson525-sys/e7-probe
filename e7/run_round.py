#!/usr/bin/env python3
"""E7 daily round (READ-ONLY): discover NEW airport domains worldwide and
probe ONLY their registration config gate. No account is created, no
registration POST is sent, no temporary-mail account is created.

Per domain, two read-only steps:
  1. raw GET <domain><prefix>guest/comm/config (prefixes /api/v1/,
     /api?scheme=) -- first-pass signal
  2. AirPort.get_register_require(domain) -- authoritative config:
     verify / invite / recaptcha / whitelist / api_prefix

Classification (same rules as the local E7 rounds):
  config_ok         -- fetch ok, not validator-blocked (four items all-no,
                       or email-verify only without a whitelist gate)
  config_unreachable-- no 200 JSON config fetched and tool returned default
  config_not_json   -- 200 but body is not JSON
  invite_force / recaptcha / whitelist_verify -- validator-blocked reasons
  blocked_429 / blocked_403 -- rate-limited / blocked, station skipped

Stations classified config_ok are CANDIDATES for the separate registration
verification step, which is NOT run by this workflow.

Writes e7-results/<YYYY-MM-DD>.json and updates e7/known-domains.json
(so every daily round probes only domains never probed before).
Records contain structure and status codes only: no email, password,
token, cookie or subscription-link contents.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E7 = os.path.join(REPO, "e7")
sys.path.insert(0, os.path.join(REPO, "subscribe"))
os.chdir(REPO)

import utils  # noqa: E402
from airport import AirPort  # noqa: E402
from discovery import (  # noqa: E402
    AskahhSource, CollectOptions, TelegramSource, YgpySource,
)

KNOWN_JSON = os.path.join(E7, "known-domains.json")
RESULTS_DIR = os.path.join(REPO, "e7-results")
MAX_DOMAINS = 20
PREFIXES = ["/api/v1/", "/api?scheme="]
INTERVAL_S = 2

NON_PANEL_HOSTS = {
    "github.com", "raw.githubusercontent.com", "gitlab.com",
    "cdn.jsdelivr.net", "gitee.com", "t.me", "telegram.me",
    "www.t.me", "www.telegram.me", "bit.ly", "reurl.cc",
}


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def norm_domain(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.startswith("http"):
        raw = "https://" + raw
    try:
        p = urllib.parse.urlsplit(raw)
    except Exception:
        return ""
    host = (p.hostname or "").lower()
    if not host or host in NON_PANEL_HOSTS:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return "https://" + host


def load_known():
    known = set()
    if os.path.exists(KNOWN_JSON):
        with open(KNOWN_JSON, encoding="utf-8") as f:
            for d in json.load(f)["domains"]:
                dd = norm_domain(d)
                if dd:
                    known.add(dd)
    return known


def discover(known):
    """New domains, worldwide, from the tool's own public sources.
    Ygpy first, then crawl channels, askahh/TelegramSource last."""
    found, seen = [], set()

    def add(domain, source):
        d = norm_domain(domain)
        if not d or d in known or d in seen:
            return False
        if len(found) >= MAX_DOMAINS:
            return False
        seen.add(d)
        found.append({"domain": d, "source": source})
        log(f"  NEW {d} (via {source}) [{len(found)}/{MAX_DOMAINS}]")
        return True

    opts = CollectOptions(num_threads=8, display=False)
    try:
        src = YgpySource()
        recs = src.crawl(opts) or []
        log(f"  source {src.name}: {len(recs)} raw records")
        for r in recs:
            add(r.domain, f"discovery:{src.name}")
    except Exception as e:
        log(f"  source ygpy FAILED: {type(e).__name__}: {str(e)[:150]}")

    if len(found) < MAX_DOMAINS:
        try:
            from config.models import ProcessConfig  # noqa: E402
            from crawl.channels import CHANNELS  # noqa: E402
            from crawl.engine import run as engine_run  # noqa: E402

            seeds = {
                "telegram": {"telegram": {"enable": True, "pages": 4, "channels": {
                    "abc_vpn_configs": {"push_to": ["e7pc"]},
                    "SylphNet": {"push_to": ["e7pc"]}}}},
                "pages": {"pages": [
                    {"enable": True,
                     "url": "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/README.md",
                     "push_to": ["e7pc"]}]},
                "repositories": {"repositories": [
                    {"enable": True, "username": "freefq", "repo": "free",
                     "commits": 10, "push_to": ["e7pc"]}]},
                "github": {"github": {"enable": True, "pages": 1, "push_to": ["e7pc"]}},
            }
            data_root = os.path.join(E7, "discovery-data")
            for channel, seed in seeds.items():
                if len(found) >= MAX_DOMAINS:
                    break
                data_dir = os.path.join(data_root, channel)
                os.makedirs(data_dir, exist_ok=True)
                raw = {
                    "sites": [], "groups": {},
                    "storage": {"engine": "local", "token": "",
                                "items": {"e7pc": {"folder_id": data_dir,
                                                   "file_id": "crawledsubs.json"}}},
                    "crawl": {"enable": True, "max_fails": 5, "include_nodes": True,
                              "persist": {"subscribe": "e7pc", "nodes": "e7pc"},
                              "task": {}},
                }
                raw["crawl"].update(seed)
                try:
                    pc = ProcessConfig.parse(raw)
                except Exception as e:
                    log(f"  channel {channel}: config parse FAILED: {e}")
                    continue
                captured = {}

                def make_wrapper(orig):
                    def wrapper(section, ctx):
                        res = orig(section, ctx)
                        captured["item_urls"] = [it.url for it in (res.items or [])]
                        return res
                    return wrapper

                ch = CHANNELS.get(channel)
                orig_crawl = ch.crawl
                ch.crawl = make_wrapper(orig_crawl)
                t1 = time.time()
                try:
                    engine_run(pc.crawl, storage=pc.storage, num_threads=8,
                               display=False, mode=1)
                except Exception as e:
                    log(f"  channel {channel} FAILED: {type(e).__name__}: {str(e)[:150]}")
                finally:
                    ch.crawl = orig_crawl
                urls = captured.get("item_urls", [])
                log(f"  channel {channel}: {len(urls)} subscription URLs "
                    f"in {round(time.time() - t1, 1)}s")
                for u in urls:
                    parts = urllib.parse.urlsplit(u)
                    if parts.hostname:
                        add(f"https://{parts.hostname}", f"crawl:{channel}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            log(f"crawl channels FAILED: {type(e).__name__}: {str(e)[:200]}")

    if len(found) < MAX_DOMAINS:
        for src in (AskahhSource(),
                    TelegramSource(channel="jichang_list", page_num=3)):
            if len(found) >= MAX_DOMAINS:
                break
            try:
                recs = src.crawl(opts) or []
            except Exception as e:
                log(f"  fallback source {src.name} FAILED: "
                    f"{type(e).__name__}: {str(e)[:150]}")
                continue
            log(f"  fallback source {src.name}: {len(recs)} raw records")
            for r in recs:
                add(r.domain, f"discovery:{src.name}")
    return found


def raw_fetch(domain, prefix):
    url = f"{domain}{prefix}guest/comm/config"
    req = urllib.request.Request(url=url, headers=dict(utils.DEFAULT_HTTP_HEADERS))
    try:
        with urllib.request.urlopen(req, timeout=8, context=utils.CTX) as resp:
            body = resp.read()
            try:
                text = body.decode("utf-8")
            except Exception:
                text = ""
            json_ok = False
            try:
                json.loads(text)
                json_ok = True
            except Exception:
                json_ok = False
            return {"status": resp.getcode(), "bytes": len(body), "json_ok": json_ok}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "bytes": 0, "json_ok": False}
    except Exception as e:
        return {"status": 0, "bytes": 0, "json_ok": False,
                "error": type(e).__name__}


def validator_blocked(req):
    return bool(
        req.invite
        or req.recaptcha
        or (req.whitelist and req.verify and "gmail.com" not in req.whitelist)
    )


def config_gate(domain):
    """Read-only config probe. Returns one record. Never registers."""
    rec = {"domain": domain, "fetch_ok": False, "raw_status": None,
           "raw_bytes": 0, "verify": None, "invite": None, "recaptcha": None,
           "whitelist": None, "api_prefix": None, "validator_blocked": None,
           "config_ok": False, "reason": ""}
    blocked_status = None
    for prefix in PREFIXES:
        raw = raw_fetch(domain, prefix)
        rec["raw_status"] = raw["status"]
        rec["raw_bytes"] = raw["bytes"]
        if raw["status"] in (429, 403):
            blocked_status = raw["status"]
            break
        if raw["status"] == 200 and raw["json_ok"]:
            rec["fetch_ok"] = True
            break
        if raw["status"] == 200 and not raw["json_ok"]:
            rec["reason"] = "config_not_json"
            continue
    if blocked_status is not None:
        rec["reason"] = f"blocked_{blocked_status}"
        return rec
    req = AirPort.get_register_require(domain)
    rec["verify"] = req.verify
    rec["invite"] = req.invite
    rec["recaptcha"] = req.recaptcha
    rec["whitelist"] = list(req.whitelist or [])
    rec["api_prefix"] = req.api_prefix
    rec["validator_blocked"] = validator_blocked(req)
    tool_config_real = not (req.verify and req.invite and req.recaptcha)
    if tool_config_real:
        rec["fetch_ok"] = True
    if not rec["fetch_ok"]:
        rec["reason"] = rec["reason"] or "config_unreachable"
    elif rec["validator_blocked"]:
        if req.invite:
            rec["reason"] = "invite_force"
        elif req.recaptcha:
            rec["reason"] = "recaptcha"
        else:
            rec["reason"] = "whitelist_verify"
    else:
        rec["reason"] = "config_ok"
        rec["config_ok"] = True
    return rec


def main():
    t0 = time.time()
    known = load_known()
    log(f"e7 round start: known set = {len(known)} domains")
    found = discover(known)
    log(f"discovery done: {len(found)} new domains")
    records, consec_blocked, aborted = [], 0, False
    for i, item in enumerate(found):
        domain = item["domain"]
        rec = config_gate(domain)
        rec["source"] = item["source"]
        if rec["reason"].startswith("blocked_"):
            consec_blocked += 1
            log(f"[{i + 1}/{len(found)}] {domain} {rec['reason']}, skipped")
            if consec_blocked >= 3:
                aborted = True
                log("3 consecutive blocked stations, aborting round")
                break
        else:
            consec_blocked = 0
            log(f"[{i + 1}/{len(found)}] {domain} -> {rec['reason']}")
        records.append(rec)
        known.add(norm_domain(domain))
        time.sleep(INTERVAL_S)
    candidates = [r["domain"] for r in records if r["config_ok"]]
    out = {
        "date": time.strftime("%Y-%m-%d"),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_s": round(time.time() - t0, 1),
        "discovered": len(found),
        "probed": len(records),
        "config_ok_count": len(candidates),
        "candidates": candidates,
        "aborted": aborted,
        "records": records,
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, time.strftime("%Y-%m-%d") + ".json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    with open(KNOWN_JSON, "w", encoding="utf-8") as f:
        json.dump({"count": len(known), "domains": sorted(known)},
                  f, ensure_ascii=False, indent=2)
    log(f"round done: {len(records)} probed, {len(candidates)} config-ok, "
        f"results -> {out_path}")
    print(json.dumps({"probed": len(records), "config_ok": len(candidates),
                      "candidates": candidates}, ensure_ascii=False))


if __name__ == "__main__":
    main()
