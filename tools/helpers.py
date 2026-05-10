"""Shared helpers for the demo scripts in this directory.

Importing this module adds the repo root to sys.path as a side effect, so the demos
can `import helpers; import sm` without each repeating the path-setup boilerplate.
"""

import sys
from contextlib import contextmanager
from email.message import EmailMessage
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import sm  # noqa: E402  (path-setup above is the prerequisite)


# ─── Email builder + sample mailbox ──────────────────────────────────────────────

def build_eml(subject, frm, body=None, html=None, attachments=None):
    """Construct an RFC822 bytes blob varying body type and attachments."""
    msg = EmailMessage()
    msg["From"] = frm
    msg["To"] = "you@example.com"
    msg["Subject"] = subject
    msg["Date"] = "Thu, 8 May 2026 14:30:00 +0000"
    msg["Message-ID"] = f"<{sha256(subject.encode()).hexdigest()[:12]}@demo>"
    if body is not None:
        msg.set_content(body)
        if html is not None:
            msg.add_alternative(html, subtype="html")
    elif html is not None:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content("(empty)")
    for filename, content in (attachments or []):
        msg.add_attachment(content, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes()


# Each entry describes one synthetic message.
# `folders` = current live folders; `removed_folders` = past folders we've left.
SAMPLES = [
    {
        "subject": "Welcome to the sm demo",
        "from": "Alice <alice@example.com>",
        "body": "Hello! This is the demo data.\n\nTry [n]ext / [p]rev / pick a number to read.\n",
        "internaldate": "10-May-2026 14:30:00 +0000",
        "folders": ["INBOX"],
    },
    {
        "subject": "Re: Lunch tomorrow at the new place that just opened on Main Street with the long name",
        "from": "Bob Long-Name <bob.long-name+suffix@super-long-domain-example.com>",
        "body": "Sure thing, see you there.\n",
        "internaldate": "09-May-2026 11:30:00 +0000",
        "folders": ["INBOX", "[Gmail]/All Mail"],  # message visible in two folders
    },
    {
        "subject": "Café reservation — Café del Mar (non-ASCII subject)",
        "from": "café@example.com",
        "body": "Confirmed. Table for 8 at Café del Mar tonight.\n",
        "internaldate": "08-May-2026 12:00:00 +0000",
        "folders": ["INBOX"],
    },
    {
        "subject": "日本からの招待状 (CJK subject)",
        "from": "tanaka@example.jp",
        "body": "こんにちは。お元気ですか。\n\nMixed scripts: hello / hola / 你好 / مرحبا\n",
        "internaldate": "07-May-2026 09:00:00 +0000",
        "folders": ["INBOX"],
    },
    {
        "subject": "Your monthly invoice (one attachment)",
        "from": "billing@example.com",
        "body": "Please find attached your invoice for May.\n",
        "internaldate": "06-May-2026 10:00:00 +0000",
        "folders": ["INBOX"],
        "attachments": [("invoice-may.pdf", b"%PDF-fake-invoice-content-here\n%%EOF\n")],
    },
    {
        "subject": "Multiple attachments (a space + non-ASCII filename)",
        "from": "automated@example.com",
        "body": "See attached: report and chart.\n",
        "internaldate": "05-May-2026 14:00:00 +0000",
        "folders": ["INBOX"],
        "attachments": [
            ("Q2 report.pdf", b"%PDF-fake-report-content"),
            ("résumé.docx", b"PK\x03\x04-fake-docx-bytes-"),
            ("chart.png", b"\x89PNG\r\n\x1a\n-fake-png-bytes-"),
        ],
    },
    {
        "subject": "HTML-only newsletter (no text/plain alternative)",
        "from": "newsletter@example.com",
        "html": "<h1>Big News!</h1><p>Lots of <b>important</b> updates.</p><br>5 &lt; 10",
        "internaldate": "04-May-2026 16:00:00 +0000",
        "folders": ["INBOX"],
    },
    {
        "subject": "Empty-bodied message",
        "from": "automated@example.com",
        "body": "",
        "internaldate": "03-May-2026 08:00:00 +0000",
        "folders": ["INBOX"],
    },
    {
        "subject": "Archived — was in INBOX, now in Archive",
        "from": "old@example.com",
        "body": "This was moved out of INBOX a while ago.\n",
        "internaldate": "01-Jan-2024 12:00:00 +0000",
        "folders": ["Archive"],
        "removed_folders": ["INBOX"],
    },
    {
        "subject": "(should NOT appear — every history entry is removed)",
        "from": "ghost@example.com",
        "body": "If you see this, is_live() filtering is broken.",
        "internaldate": "01-Jan-2023 00:00:00 +0000",
        "folders": [],
        "removed_folders": ["INBOX", "Archive"],
    },
]


def populate_store_with_samples(store):
    """Write SAMPLES messages + per-folder UIDVALIDITY into the given Store (already entered)."""
    next_uid = {}
    for entry in SAMPLES:
        raw = build_eml(
            subject=entry["subject"],
            frm=entry["from"],
            body=entry.get("body"),
            html=entry.get("html"),
            attachments=entry.get("attachments"),
        )
        content_hash = sha256(raw).hexdigest()
        (store.mails_path / f"{content_hash}.eml").write_bytes(raw)

        history = []
        for folder in entry["folders"]:
            uid = next_uid.get(folder, 1)
            next_uid[folder] = uid + 1
            history.append({"folder": folder, "uid": uid})
        for folder in entry.get("removed_folders", []):
            uid = next_uid.get(folder, 1)
            next_uid[folder] = uid + 1
            history.append({"folder": folder, "uid": uid, "removed": True})

        store.messages[content_hash] = {
            "message_id": f"<{content_hash[:12]}@demo>",
            "subject": entry["subject"],
            "from": entry["from"],
            "date": "Thu, 8 May 2026 14:30:00 +0000",
            "internaldate": entry["internaldate"],
            "history": history,
        }
    store.folder_states["INBOX"] = {"uidvalidity": 1}
    store.folder_states["Archive"] = {"uidvalidity": 1}
    store.save()


# ─── Sample errors (used by both the sync-error demo and the read-with-errors demo) ──

# One sample per ErrorEvent.kind the codebase actually emits, plus duplicates to show grouping.
SAMPLE_ERRORS = [
    ("parse_list", "non-bytes/tuple input", b"42"),
    ("parse_list", "no opening paren on flag list", b"totally bogus line from the server"),
    ("parse_list", "unterminated flag list", b"(\\HasNoChildren) "),
    ("parse_list", "folder name contains disallowed byte 0x0d", b"() \"/\" {7}\r\nINBOX\rX"),
    ("select_failed", "SELECT returned NO for folder '[Old]/Trashed'", None),
    ("select_error", "SELECT raised TimeoutError for folder 'Slow Folder': read timed out", None),
    ("unsafe_folder_name", "folder 'INBOX\\r\\nA1 LOGOUT' contains disallowed bytes; refusing to SELECT", None),
    ("uidvalidity_changed", "folder 'INBOX' UIDVALIDITY changed from 1 to 999; cache invalidated", None),
]


def populate_ctx_with_errors(ctx, errors=None):
    """Record SAMPLE_ERRORS (or a custom list of (kind, detail, raw) tuples) onto the given ctx."""
    for kind, detail, raw in (errors if errors is not None else SAMPLE_ERRORS):
        ctx.record_error(kind, detail, raw=raw)


# ─── Tempdir mailbox context manager ─────────────────────────────────────────────

@contextmanager
def with_demo_store():
    """Set up a tempdir, override sm.LOCK_PATH, populate a Store with SAMPLES, yield
    (store_path, account, ctx). Caller may pre-populate ctx.errors before invoking sm
    APIs. Tempdir is cleaned up on exit."""
    with TemporaryDirectory(prefix="sm-demo-") as tmp:
        tmp_path = Path(tmp)
        sm.LOCK_PATH = tmp_path / ".lock"  # don't touch the real user's lock file
        store_path = tmp_path / "store"
        with sm.Store(store_path) as store:
            populate_store_with_samples(store)
        ctx = sm.Context()
        account = sm.MailConnectionInfos(name="demo", local_store_path=str(store_path))
        yield store_path, account, ctx
