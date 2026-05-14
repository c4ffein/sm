#!/usr/bin/env python3
"""Demo launcher for sm's folder menu + preset filters. Populates a synthetic mailbox
scattered across many folders and configures named folder presets, so you can drive
the modal interactively without a real account.

Run from repo root:
    python3 tools/demo_folder_menu.py

Once inside the read UI, press [m] to open the folder menu:
  - j/l navigates the preset row (j/l labels are: [none], business, personal,
    receipts-only, future-only, [custom])
  - i/k navigates the folder list
  - Space applies the preset at the j/l cursor, or toggles the folder at the i/k cursor
  - Toggling a folder switches the active selection to [custom]
  - Enter commits and persists to state.json; Esc cancels

Notable bits the fixture exercises:
  - 12 folders so the menu scrolls past most terminal heights.
  - One preset ("future-only") references a folder ("NonExistent") that has no
    messages — it still appears in the folder list because the menu unions the
    snapshot's folders with every folder named in any preset.
"""

import helpers

import sm

FOLDERS = [
    "INBOX",
    "Archive",
    "[Gmail]/All Mail",
    "[Gmail]/Spam",
    "[Gmail]/Drafts",
    "[Gmail]/Trash",
    "Projects/Client A",
    "Projects/Client B",
    "Family",
    "Newsletters",
    "Receipts",
    "Travel",
]

PRESETS = {
    "business": ["INBOX", "Projects/Client A", "Projects/Client B"],
    "personal": ["INBOX", "Family", "Newsletters"],
    "receipts-only": ["Receipts"],
    # Preset-only folder — has no messages locally, but still shows up in the menu.
    "future-only": ["NonExistent"],
}


def main():
    samples = helpers.multi_folder_samples(FOLDERS, n_per_folder=3)
    with helpers.with_demo_store(samples=samples, folder_presets=PRESETS) as (store_path, account, ctx):
        print()
        print(f"  sm demo (folder menu) — synthetic mailbox at {store_path}")
        print(f"  {len(FOLDERS)} folders, {len(samples)} messages, {len(PRESETS)} presets")
        print("  Press [m] in the read UI to drive the folder menu.")
        print()
        sm.read_emails(account, ctx)


if __name__ == "__main__":
    main()
