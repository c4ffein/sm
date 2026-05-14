#!/usr/bin/env python3
"""Demo launcher for sm's read UI with pre-populated errors on the Context. Same synthetic
mailbox as demo_read_ui.py, plus a handful of recorded ErrorEvents so the [e]rrors action
appears in the list-view action line. Press [e] to view the grouped detail screen.

Run from repo root:
    python3 tools/demo_read_with_errors.py            # curated SAMPLES only
    python3 tools/demo_read_with_errors.py 500        # SAMPLES + 500 numbered stress-test samples

For the no-errors variant, see demo_read_ui.py.
"""

import sys

import helpers

import sm


def main():
    extra = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    visible = sum(1 for s in helpers.SAMPLES if s["folders"])
    hidden = len(helpers.SAMPLES) - visible
    with helpers.with_demo_store(extra_numbered=extra) as (store_path, account, ctx):
        helpers.populate_ctx_with_errors(ctx)
        print()
        print(f"  sm demo (with errors) — synthetic mailbox at {store_path}")
        suffix = f" + {extra} numbered stress-test sample(s)" if extra else ""
        print(f"  {visible} visible / {hidden} hidden by is_live() filter{suffix}")
        print(f"  {len(ctx.errors)} pre-populated errors — try [e] from the list view")
        print()
        sm.read_emails(account, ctx)


if __name__ == "__main__":
    main()
