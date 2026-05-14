#!/usr/bin/env python3
"""Demo launcher for sm's read UI — clean state (no errors). Populates a tempdir mailbox
with synthetic mail and launches the interactive reader. The list view does NOT show the
[e]rrors action because ctx.errors is empty.

Run from repo root:
    python3 tools/demo_read_ui.py            # curated SAMPLES only
    python3 tools/demo_read_ui.py 500        # SAMPLES + 500 numbered stress-test samples

For the with-errors variant, see demo_read_with_errors.py.
"""

import sys

import helpers

import sm


def main():
    extra = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    visible = sum(1 for s in helpers.SAMPLES if s["folders"])
    hidden = len(helpers.SAMPLES) - visible
    with helpers.with_demo_store(extra_numbered=extra) as (store_path, account, ctx):
        print()
        print(f"  sm demo (clean state) — synthetic mailbox at {store_path}")
        suffix = f" + {extra} numbered stress-test sample(s)" if extra else ""
        print(f"  {visible} visible / {hidden} hidden by is_live() filter{suffix}")
        print("  No errors pre-populated; the [e]rrors action will not appear.")
        print()
        sm.read_emails(account, ctx)


if __name__ == "__main__":
    main()
