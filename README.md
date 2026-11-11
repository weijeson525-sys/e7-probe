# e7-probe

Daily, worldwide hunt for airport panels with a usable free plan — running
on GitHub Actions. Finds new panels, checks their registration config, and
verifies the ones that pass by actually registering.

## What it does (once a day, 00:00 UTC)

1. **Discover** up to 20 NEW airport domains from public sources
   (Ygpy, crawl channels, askahh, Telegram) that were never probed before.
   The exclusion set lives in `e7/known-domains.json` and grows every round.
2. **Probe only the registration config gate** of each new domain:
   raw GET of `guest/comm/config` plus the tool's own
   `AirPort.get_register_require`. Records verify / invite / recaptcha /
   whitelist and classifies each domain (`config_ok`, `config_unreachable`,
   `config_not_json`, `invite_force`, `recaptcha`, `whitelist_verify`,
   `blocked_429` / `blocked_403`). Results go to
   `e7-results/<YYYY-MM-DD>.json`.
3. **Verify the config_ok candidates** (`e7/run_verify.py`): register with
   a throwaway Emailnator temporary gmail, check for a free plan, fetch
   the subscription, count node URIs, and TCP-probe each node endpoint
   (3s timeout). Results go to `e7-results/<YYYY-MM-DD>-verify.json`.
   "Usable node" = a node endpoint that accepted a TCP connection. It is
   a liveness proxy, not a full protocol check.
4. **Commit results** to `e7-results/` and push.

## What it does NOT do

- No real user account is used: registration uses throwaway temporary
  mail and random passwords, never the operator's email, never stored.
- No credentials, no tokens, no subscription links, no node URIs in
  results — records hold booleans, counts, and reasons only. Runner logs
  may contain a one-time 6-digit verification code for a throwaway temp
  account if mask extraction fails; that code is single-use and expires
  within minutes.

## Method

Built from [wzdnzd/aggregator](https://github.com/wzdnzd/aggregator)
(Apache-2.0, see `LICENSE`): the `subscribe/` package plus the E7
discovery/config-gate/verify logic. The tool was designed to run on a
runner; this repo runs it on a schedule, worldwide.

## Known limitations

- `subscribe/utils.py` disables TLS verification globally (upstream
  behaviour, documented in the lab report); config fetches inherit it.
- A runner's shared cloud IP may be blocked by some panels' anti-bot
  checks; those stations land in `blocked_403` / `config_unreachable`.
- `config_unreachable` cannot distinguish "site down" from "invite forced":
  when the config cannot be fetched, the tool returns all-True defaults.
- Emailnator is the only mail path that has been wired in; if its
  endpoint is blocked from the runner, registration fails for that round.
