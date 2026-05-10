#!/usr/bin/env python3
"""Demo launcher for sm's sync-time error summary UI. Builds a Context at each verbosity
level, pre-populates it with one sample per error kind the codebase emits, and renders
the summary so you can see what users would see on a real sync that hit these errors.

Run from repo root:
    python3 tools/demo_sync_errors.py

No real configuration is touched.
"""

import helpers
import sm


def main():
    for v in (sm.Verbosity.ERROR, sm.Verbosity.INFO, sm.Verbosity.DEBUG):
        print(f"\n──── verbosity = {v.name} ────")
        ctx = sm.Context(param=sm.Param(verbosity=v))
        helpers.populate_ctx_with_errors(ctx)
        sm._summarize_errors(ctx)
    print()


if __name__ == "__main__":
    main()
