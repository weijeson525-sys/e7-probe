#!/usr/bin/env python3
"""E7 Gmail phase 1 (REG-53): send verification codes to real Gmail
+suffix aliases for today's gmail-whitelist candidates.

Why: Emailnator (temp gmail) is dead from the runner -- the server
returns 200 but sets ZERO Set-Cookie headers, so no XSRF token can be
obtained (run #5 diag). MailTM has no domains either. The panels'
whitelists only accept real providers (gmail/qq/163), so the only
working gmail path is a real Gmail address with a +suffix alias.

Privacy rules (hard):
- The Gmail address comes from the GMAIL_USER env var (a
  workflow_dispatch input). It is NEVER printed and NEVER written to
  any file in this repo.
- The pending file e7-results/<date>-gmail-pending.json holds ONLY
  {site, tag, sent_at}. The alias is local-part + "+" + tag +
  "@gmail.com"; the local-part lives only in the dispatch input and in
  the orchestrator's memory, never in the repo.
- Tags are random per site; a tag alone reveals nothing.

Usage: GMAIL_USER=someone@gmail.com python e7/run_gmail_phase1.py [--limit N]
"""
import json
import os
import secrets
import sys
import time
import urllib.parse
import urllib.request
from copy import deepcopy

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "subscribe"))
os.chdir(REPO)

import utils  # noqa: E402
from airport import ANOTHER_API_PREFIX, AirPort  # noqa: E402


def to_ascii_site(domain: str) -> str:
    """IDNA-encode a non-ASCII host so urllib can use it."""
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


def verbose_send(ap: AirPort, alias: str, retry: int = 3) -> tuple[bool, str]:
    """Same POST as AirPort.sen_email_verify, but returns the reason.
    The alias is redacted from every logged value."""
    params = {"email": alias.strip()}
    data = urllib.parse.urlencode(params).encode(encoding="UTF8")
    headers = deepcopy(ap.headers)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    if ap.api_prefix == ANOTHER_API_PREFIX:
        headers["Content-Type"] = "application/json"
        data = json.dumps(params).encode(encoding="UTF8")
    last = "no_attempt"
    for _ in range(retry):
        try:
            request = urllib.request.Request(ap.send_email, data=data,
                                             headers=headers, method="POST")
            response = urllib.request.urlopen(request, timeout=10, context=utils.CTX)
            status = response.getcode()
            body = response.read().decode("utf-8", "replace")[:300]
            body = body.replace(alias, "<alias>")
            if status != 200:
                last = f"http_{status}:{body}"
                continue
            try:
                payload = json.loads(body)
            except Exception:
                last = f"not_json:{body}"
                continue
            if payload.get("data"):
                return True, "ok"
            last = f"data_false:{body}"
        except Exception as e:
            last = f"exc:{type(e).__name__}:{str(e)[:120].replace(alias, '<alias>')}"
        time.sleep(1)
    return False, last


def main() -> int:
    gmail_user = os.environ.get("GMAIL_USER", "").strip()
    if not gmail_user.endswith("@gmail.com") or "+" in gmail_user.split("@")[0]:
        print("gmail phase1: GMAIL_USER must be a plain @gmail.com address")
        return 2
    local = gmail_user.split("@")[0]
    limit = 3
    sites_arg = ""
    if "--limit" in sys.argv:
        try:
            limit = int(sys.argv[sys.argv.index("--limit") + 1])
        except Exception:
            pass
    if "--sites" in sys.argv:
        try:
            sites_arg = sys.argv[sys.argv.index("--sites") + 1].strip()
        except Exception:
            sites_arg = ""
    date = time.strftime("%Y-%m-%d", time.gmtime())
    src_path = os.path.join(REPO, "e7-results", f"{date}.json")
    if not os.path.exists(src_path):
        print(f"gmail phase1: no results file {src_path}")
        return 0
    with open(src_path, encoding="utf-8") as f:
        src = json.load(f)
    records = {r["domain"]: r for r in src.get("records", [])}
    candidates = [d for d in src.get("candidates", [])
                  if records.get(d, {}).get("verify")
                  and "gmail.com" in (records[d].get("whitelist") or [])]
    pending_path = os.path.join(REPO, "e7-results", f"{date}-gmail-pending.json")
    pending = {}
    if os.path.exists(pending_path):
        try:
            with open(pending_path, encoding="utf-8") as f:
                pending = {p["site"]: p for p in json.load(f).get("pending", [])}
        except Exception:
            pending = {}
    todo = [d for d in candidates if d not in pending][:limit]
    bare_sites: set = set()
    if sites_arg:
        # Explicit retest: resend to exactly these sites, ignoring pending.
        # A "bare:" prefix means the panel rejects Gmail aliases: send to
        # the bare address (no +suffix) and store tag "bare".
        todo = []
        bare_sites = set()
        for d in sites_arg.split(","):
            d = d.strip()
            if not d:
                continue
            if d.startswith("bare:"):
                d = d[5:]
                bare_sites.add(d)
            todo.append(d)
        todo = [d for d in todo if d in candidates]
    print(f"gmail phase1: {len(candidates)} gmail candidates, {len(todo)} to send")
    sent = 0
    for domain in todo:
        if domain in bare_sites:
            tag = "bare"
            alias = f"{local}@gmail.com"
        else:
            tag = secrets.token_hex(4)
            alias = f"{local}+{tag}@gmail.com"
        try:
            ap = AirPort(name=domain, site=to_ascii_site(domain))
            rr = AirPort.get_register_require(domain, default=False)
            ap.api_prefix = rr.api_prefix or ap.api_prefix
            ok, why = verbose_send(ap, alias, retry=3)
        except Exception as e:
            ok, why = False, f"setup_exc:{type(e).__name__}"
        # Never print the alias.
        print(f"gmail phase1: {domain} send={'ok' if ok else 'failed'} reason={why}")
        if ok:
            pending[domain] = {"site": domain, "tag": tag,
                               "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            sent += 1
        time.sleep(2)
    with open(pending_path, "w", encoding="utf-8") as f:
        json.dump({"date": date, "pending": list(pending.values())},
                  f, ensure_ascii=False, indent=2)
    print(f"gmail phase1 done: {sent} codes sent, pending file -> {pending_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
