#!/usr/bin/env python3
"""Demo launcher for sm's read UI with pre-populated errors on the Context. Same synthetic
mailbox as demo_read_ui.py, plus a handful of recorded ErrorEvents so the [e]rrors action
appears in the list-view action line. Press [e] to view the grouped detail screen.

Run from repo root:
    python3 tools/demo_read_with_errors.py

For the no-errors variant, see demo_read_ui.py.
"""

import helpers
import sm


def main():
    visible = sum(1 for s in helpers.SAMPLES if s["folders"])
    hidden = len(helpers.SAMPLES) - visible
    with helpers.with_demo_store() as (store_path, account, ctx):
        helpers.populate_ctx_with_errors(ctx)
        print()
        print(f"  sm demo (with errors) — synthetic mailbox at {store_path}")
        print(f"  {visible} visible / {hidden} hidden by is_live() filter")
        print(f"  {len(ctx.errors)} pre-populated errors — try [e] from the list view")
        print()
        sm.read_emails(account, ctx)


if __name__ == "__main__":
    main()
