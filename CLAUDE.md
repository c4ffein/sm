# Notes for Claude

Single-file PoC mail client (`sm.py`). Stdlib-only. KISS.

## Before declaring code "ready to commit"

Run `make verify`. It runs:

- `ruff check --no-fix` + `ruff format --check` — no auto-fix, just verify clean.
- The test suite (`python3 -m unittest discover tests`).

Don't auto-commit; the user does the commits.

## Useful Make targets

- `make verify` — read-only "is this branch ready?" check. Run before declaring done.
- `make lint` — auto-fix style + format (mutates files). Use during iteration.
- `make lint-check` — same as the lint half of verify.
- `make test` — just the tests (~18s; integration tests use a real TLS fake server, so they need `openssl` — skip cleanly if absent).

If ruff isn't installed: `pip install -e .[dev]` (the project's dev extras include it).

## Project conventions

- **Errors flow through `ctx.record_error(kind, detail, raw=None)`.** Don't print errors directly; record them and let the UI surface them via `_summarize_errors` (sync) or `_show_errors_screen` (read UI's `[e]` action).
- **"Is this message gone?" is `is_gone(entry)`** — derived from history (every entry has `removed: True`). There's no top-level `entry["deleted"]` flag.
- **Atomic saves**: every disk write goes via temp file + `rename`. Never write directly to `index.json`.
- **TLS uses `make_pinned_ssl_context`** (SHA-256 cert pinning). Don't trust the system CA store; servers must match the configured pin.
- **Folder names from the server pass through `_is_safe_folder_name`** — defense in depth: rejected at the parser AND at the SELECT call site.
- **Demos under `tools/`** — runnable scripts, not tests; use them for manual UI review. Shared building blocks live in `tools/helpers.py`.
