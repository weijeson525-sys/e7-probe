# e7-probe

Daily, worldwide hunt for airport panels whose registration config is
reachable — running on GitHub Actions, read-only.

## What it does (once a day, 00:00 UTC)

1. **Discover** up to 20 NEW airport domains from public sources
   (Ygpy, crawl channels, askahh, Telegram) that were never probed before.
   The exclusion set lives in `e7/known-domains.json` and grows every round.
2. **Probe only the registration config gate** of each new domain:
   raw GET of `guest/comm/config` plus the tool's own
   `AirPort.get_register_require`. Records verify / invite / recaptcha /
   whitelist and classifies each domain (`config_ok`, `config_unreachable`,
   `config_not_json`, `invite_force`, `recaptcha`, `whitelist_verify`,
   `blocked_429` / `blocked_403`).
3. **Commit results** to `e7-results/<YYYY-MM-DD>.json` and push.

## What it does NOT do

- No account is created. No registration POST is sent. No temporary-mail
  account is created. Registration verification of `config_ok` candidates
  is a separate step, done elsewhere.
- No credentials, no tokens, no subscription links in results — records
  hold structure and status codes only.

## Method

Built from [wzdnzd/aggregator](https://github.com/wzdnzd/aggregator)
(Apache-2.0, see `LICENSE`): the `subscribe/` package plus the E7
discovery/config-gate logic. The tool was designed to run on a runner;
this repo runs only its read-only half, on a schedule, worldwide.

## Known limitations

- `subscribe/utils.py` disables TLS verification globally (upstream
  behaviour, documented in the lab report); config fetches inherit it.
- A runner's shared cloud IP may be blocked by some panels' anti-bot
  checks; those stations land in `blocked_403` / `config_unreachable`.
- `config_unreachable` cannot distinguish "site down" from "invite forced":
  when the config cannot be fetched, the tool returns all-True defaults.
