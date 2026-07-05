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
    "sender_name": "Jane Doe"  (optional, From: display name for send)
    "pinned_imap_certificate_sha256": "XX"
    "smtp_ssl_host": "XX"
    "smtp_ssl_port": 587
    "pinned_smtp_certificate_sha256": "XX"
    "local_store_path": "XX"
    "ssl_cafile": "/optional/override"  (overrides global)
    "folder_presets": {"business": ["Work", "Projects"], "personal": ["INBOX"]}  (optional, for read UI)
───────────────────────
- sm send recipient=a@b.com [recipient=...] [cc=...] (subject=title|subject-answer=orig)
      (body=text|body-file=path) [account=name] [file=path] [in-reply-to=<id>] [references="<id1> <id2>"]
      ──➤ subject-answer= prepends 'Re: ' idempotently; body-file= reads UTF-8 from path
- sm send-patches recipient=a@b.com [recipient=...] patch=0001.patch [patch=...] [account=name] [dry-run]
    ──➤ send git format-patch files inline + threaded (kernel-style); dry-run prints, sends nothing
    ──➤ In-Reply-To/References in the first patch (format-patch --in-reply-to) join that existing thread
- sm sync [account=name] [yes] [verbose=0|1|2]      ──➤ fetch new + review deletions/moves
- sm read [account=name]                             ──➤ read emails in terminal
- sm resync-internaldate [account=name]              ──➤ backfill missing INTERNALDATE (no body fetch)
───────────────────────
  verbose= accepts 0/1/2 or error/info/debug (applies to all commands)
You need to generate an app specific password for gmail or other mail clients
```

## Sending a patch series (kernel-style)

`sm send-patches` sends `git format-patch` files the way `git send-email` does:
inline `text/plain` (never MIME-multipart or base64), body bytes byte-exact so
`git am` reconstructs the commit verbatim, UTF-8 over 8bit transfer encoding
(names like François, em-dashes in comments survive), the patch's own `From:`
preserved, and each message threaded under the first via `In-Reply-To` /
`References` so a cover letter + 1/N + 2/N land as one thread.

```sh
# preview without sending (prints each fully-formed message):
sm send-patches recipient=maint@kernel.org patch=0000-cover.patch \
    patch=0001-fix.patch patch=0002-test.patch dry-run

# then actually send:
sm send-patches recipient=maint@kernel.org [recipient=reviewer@x ...] \
    patch=0000-cover.patch patch=0001-fix.patch patch=0002-test.patch [account=name]
```

The SMTP envelope sender is always the configured account; recipients apply to
every message in the series. This was built to send a real Linux kernel patch
and verified by round-tripping the output back through `git am`.

## Demo

Three demo scripts under `tools/` exercise different parts of the UI without configuring a real account. Each populates synthetic data into a tempdir / Context; no real config is touched.

```
python3 tools/demo_read_ui.py            # read UI, clean state — no errors, no [e] action
python3 tools/demo_read_with_errors.py   # read UI with pre-populated errors → press [e]
python3 tools/demo_sync_errors.py        # sync error summary at each verbosity level
```

Shared building blocks live in `tools/helpers.py` (sample mailbox, sample errors, tempdir setup).
