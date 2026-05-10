# sm
KISS cli mail client, in Python

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.

## Help
```
sm - Simple Mail client
───────────────────────
~/.config/sm/config.json ──➤ {"accounts": [ACCOUNT_INFOS, ACCOUNT_INFOS, ...], ...}
  - optional: "default_account_for_send": "account_name"
  - optional: "ssl_cafile": "/path/to/ca-bundle.crt"  (global default)
  - ACCOUNT_INFOS = {
    "name": "XX"
    "imap_ssl_host": "XX"
    "imap_ssl_port": 993
    "username": "XX"
    "password": "XX"
    "pinned_imap_certificate_sha256": "XX"
    "smtp_ssl_host": "XX"
    "smtp_ssl_port": 587
    "pinned_smtp_certificate_sha256": "XX"
    "local_store_path": "XX"
    "ssl_cafile": "/optional/override"  (overrides global)
───────────────────────
- sm send recipient=a@b.com [recipient=c@d.com ...] subject=title body=something [account=name] [file=path]
- sm sync [account=name] [yes] [verbose=0|1|2]      ──➤ fetch new + review deletions/moves
- sm read [account=name]                            ──➤ read emails in terminal
───────────────────────
  verbose= accepts 0/1/2 or error/info/debug (applies to all commands)
You need to generate an app specific password for gmail or other mail clients
```

## Demo

Three demo scripts under `tools/` exercise different parts of the UI without configuring a real account. Each populates synthetic data into a tempdir / Context; no real config is touched.

```
python3 tools/demo_read_ui.py            # read UI, clean state — no errors, no [e] action
python3 tools/demo_read_with_errors.py   # read UI with pre-populated errors → press [e]
python3 tools/demo_sync_errors.py        # sync error summary at each verbosity level
```

Shared building blocks live in `tools/helpers.py` (sample mailbox, sample errors, tempdir setup).
