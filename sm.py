#!/usr/bin/env python

"""
sm - Simple Mail client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
"""

import os
import re
from dataclasses import dataclass, fields
from email import encoders, message_from_bytes
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from enum import Enum
from hashlib import sha256
from imaplib import IMAP4_SSL
from json import dumps, loads
from pathlib import Path
from smtplib import SMTP, SMTPAuthenticationError
from socket import gaierror
from socket import timeout as socket_timeout
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLCertVerificationError,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import argv
from sys import flags as sys_flags
from urllib.error import HTTPError
from uuid import uuid4

CONFIG_PATH = Path.home() / ".config" / "sm" / "config.json"
LOCK_PATH = Path.home() / ".config" / "sm" / ".lock"

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])

Verbosity = Enum("Verbosity", [("ERROR", 0), ("INFO", 1), ("DEBUG", 2)])
_verbosity = Verbosity.ERROR


def log(msg, level=Verbosity.INFO):
    if level.value <= _verbosity.value:
        print(msg)


SAFE_PRINT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " -.,;:!?/\\@#$%&*()[]{}=+_'\"<>~`^|"
    "\t\n\r"
)


def safe_str(text, allow_newlines=True):
    allowed = SAFE_PRINT_CHARS if allow_newlines else SAFE_PRINT_CHARS - {"\n", "\r"}
    return "".join(c if c in allowed else "\ufffd" for c in str(text))


ALLOWED_NAME_CHARS = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789.-_"


def make_pinned_ssl_context(pinned_sha_256, cafile=None, capath=None, cadata=None):
    """
    Returns an instance of a subclass of SSLContext that uses a subclass of SSLSocket
    that actually verifies the sha256 of the certificate during the TLS handshake
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:
                raise SSLCertVerificationError("Incorrect certificate checksum")

        def do_handshake(self, *args, **kwargs):
            r = super().do_handshake(*args, **kwargs)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH):
        if not isinstance(purpose, _ASN1Object):
            raise TypeError(purpose)
        if purpose == Purpose.SERVER_AUTH:  # Verify certs and host name in client mode
            context = PinnedSSLContext(PROTOCOL_TLS_CLIENT)
            context.verify_mode, context.check_hostname = CERT_REQUIRED, True
        elif purpose == Purpose.CLIENT_AUTH:
            context = PinnedSSLContext(PROTOCOL_TLS_SERVER)
        else:
            raise ValueError(purpose)
        context.verify_flags |= _ssl.VERIFY_X509_STRICT
        if cafile or capath or cadata:
            context.load_verify_locations(cafile, capath, cadata)
        elif context.verify_mode != CERT_NONE:
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, may fail silently
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys_flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()


class SMException(Exception):
    pass


def raise_smexception_on_connection_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SMException:
            raise
        except HTTPError as exc:
            raise SMException(f"HTTP Error when reaching server: {exc.code}") from exc
        except socket_timeout as exc:
            raise SMException("Timed out") from exc
        except Exception as exc:
            if isinstance(getattr(exc, "reason", None), socket_timeout):
                raise SMException("TLS timed out") from exc  # Most probable cause, should check this is always the case
            if isinstance(getattr(exc, "reason", None), gaierror):
                raise SMException("Failed domain name resolution") from exc
            if isinstance(getattr(exc, "reason", None), SSLCertVerificationError):
                raise SMException("Failed SSL cert validation") from exc
            if isinstance(exc, gaierror):
                raise SMException("Failed domain name resolution") from exc
            if isinstance(exc, SSLCertVerificationError):
                raise SMException("Failed SSL cert validation") from exc
            # Keeping this as-is for now, should not happen if everything is handled correctly, add any necessary ones
            raise SMException("Unknown error when trying to reach server") from exc

    return wrapper



class Store:
    _active = False

    def __init__(self, local_store_path):
        self.store_path = Path(local_store_path)
        self.mails_path = self.store_path / "mails"
        self.index = None

    def __enter__(self):
        if Store._active:
            raise SMException("Store is already open")
        Store._active = True
        try:
            with LOCK_PATH.open("x"):
                pass
        except FileExistsError:
            Store._active = False
            raise SMException(
                f"Failed to acquire lock.\nIf no instance of the tool is running, you may remove: {LOCK_PATH}"
            ) from None
        try:
            self.mails_path.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.index = self._load_index()
        except OSError as exc:
            LOCK_PATH.unlink()
            Store._active = False
            raise SMException(f"Failed to initialize local store at {self.store_path}: {exc}") from exc
        return self

    def __exit__(self, *exc):
        LOCK_PATH.unlink()
        Store._active = False

    def _load_index(self):
        index_path = self.store_path / "index.json"
        if index_path.exists():
            content = index_path.read_text()
            if not content.strip():
                return {}
            return loads(content)
        return {}

    def save_index(self):
        if not Store._active:
            raise SMException("Cannot save index outside of Store context")
        index_path = self.store_path / "index.json"
        temp_path = self.store_path / ".index.json.tmp"
        with temp_path.open("w") as f:
            f.write(dumps(self.index, indent=2))
        temp_path.rename(index_path)


@dataclass
class MailConnectionInfos:
    name: str = None
    imap_ssl_host: str = None
    imap_ssl_port: int = None
    pinned_imap_certificate_sha256: str = None
    smtp_ssl_host: str = None
    smtp_ssl_port: int = None
    pinned_smtp_certificate_sha256: str = None
    username: str = None
    password: str = None
    local_store_path: str = None
    ssl_cafile: str = None

    @classmethod
    def from_dict(cls, d: dict):
        valid = {f.name for f in fields(cls)}
        invalid = set(d.keys()) - valid
        if invalid:
            raise SMException(f"Wrong argument for account in config: {', '.join(invalid)}")
        return cls(**d)


def save_attachment(store_path: Path, msg):
    for file_name in ["index", "files", "mails"]:
        (Path(store_path) / file_name).mkdir(mode=0o700, parents=True, exist_ok=True)
    returned_paths = []
    att_path = "No attachment found."
    for part in msg.walk():
        if (part.get_content_maintype() == "multipart") or (part.get("Content-Disposition") is None):
            continue
        filename = part.get_filename() or "UNKNOWN"
        filename = "".join(c for c in filename.lower().replace(" ", "_") if c in ALLOWED_NAME_CHARS)
        filename = "".join(str(uuid4()).split("-")[:3]) + "-" + filename
        att_path = store_path / "files" / filename
        if not att_path.is_file():
            content = part.get_payload(decode=True)
            if not content:
                continue
            with att_path.open("wb") as fp:
                fp.write(content)
        returned_paths.append(att_path)
    return returned_paths


@raise_smexception_on_connection_error
def _fetch_all_emails(account: MailConnectionInfos, store: Store):
    """Core: connect, iterate all folders/UIDs, download new emails, update index.
    Returns (server_state, new_count).
    server_state = {content_hash: [{"folder": ..., "uid": ...}, ...]}
    """
    ssl_context = make_pinned_ssl_context(account.pinned_imap_certificate_sha256, cafile=account.ssl_cafile)
    mail = IMAP4_SSL(account.imap_ssl_host, account.imap_ssl_port, ssl_context=ssl_context)
    mail.login(account.username, account.password)

    try:
        status, folder_data = mail.list()
        folders = []
        for item in folder_data:
            if isinstance(item, bytes):
                parts = item.decode().rsplit('" "', 1)
                if len(parts) == 2:
                    folders.append(parts[1].rstrip('"'))
        if not folders:
            raise SMException(f"No folders found. Raw response: {folder_data[:3]}...")

        # Build reverse lookup: (folder, uid) -> content_hash from existing index
        # TODO: UIDVALIDITY — IMAP assigns a UIDVALIDITY value per folder (returned on SELECT).
        #   As long as it stays the same, UIDs are stable and never reused. If it changes (server
        #   rebuild, migration, etc.), all cached (folder, uid) mappings are invalid.
        #   We should store UIDVALIDITY per folder in the index, check it on SELECT, and when it
        #   changes, invalidate cached UIDs for that folder and re-fetch to re-link emails to new UIDs.
        known_uids = {}
        for content_hash, entry in store.index.items():
            for h in entry.get("history", []):
                known_uids[(h["folder"], h["uid"])] = content_hash

        server_state = {}
        new_count = 0

        for folder in folders:
            try:
                status, messages = mail.select(f'"{folder}"')
                if status != "OK":
                    log(f"Skipping folder (select failed): {safe_str(folder, allow_newlines=False)}", Verbosity.DEBUG)
                    continue  # TODO: collect into structured warnings to surface in sync summary
            except Exception:
                log(f"Skipping folder: {safe_str(folder, allow_newlines=False)}", Verbosity.DEBUG)
                # TODO: collect into structured warnings to surface in sync summary
                continue

            result, data = mail.uid("SEARCH", None, "ALL")
            if not data[0]:
                continue
            uids = [int(s) for s in data[0].split()]
            print(f"  {safe_str(folder, allow_newlines=False)}: {len(uids)} email(s)")

            for i, uid in enumerate(uids, 1):
                cached_hash = known_uids.get((folder, uid))
                if cached_hash and (store.mails_path / f"{cached_hash}.eml").exists():
                    server_state.setdefault(cached_hash, []).append({"folder": folder, "uid": uid})
                    print(f"\r    {i}/{len(uids)}", end="", flush=True)
                    continue

                result, data = mail.uid("fetch", str(uid), "(RFC822 INTERNALDATE)")
                for response_part in data:
                    if not isinstance(response_part, tuple):
                        continue
                    raw_email = response_part[1]
                    content_hash = sha256(raw_email).hexdigest()

                    server_state.setdefault(content_hash, []).append({"folder": folder, "uid": uid})

                    header = response_part[0].decode() if isinstance(response_part[0], bytes) else ""
                    internaldate = ""
                    if "INTERNALDATE" in header:
                        start = header.find('INTERNALDATE "') + 14
                        end = header.find('"', start)
                        internaldate = header[start:end]

                    if content_hash in store.index:
                        existing = store.index[content_hash]
                        existing.pop("deleted", None)
                        folder_names = [h["folder"] for h in existing.get("history", [])]
                        if folder not in folder_names:
                            existing.setdefault("history", []).append({"folder": folder, "uid": uid})
                            store.save_index()
                    else:
                        # New email (or orphan recovery)
                        email_data = message_from_bytes(raw_email)
                        eml_path = store.mails_path / f"{content_hash}.eml"

                        if eml_path.exists():
                            # Paranoid mode: orphan .eml exists, verify content matches
                            with eml_path.open("rb") as f:
                                existing_hash = sha256(f.read()).hexdigest()
                            if existing_hash != content_hash:
                                raise SMException(
                                    f"Corruption detected: {eml_path} hash mismatch "
                                    f"(expected {content_hash}, got {existing_hash})"
                                )
                            # Orphan recovered, just index it
                        else:
                            # Atomic write: temp file + rename
                            temp_path = store.mails_path / f".{content_hash}.eml.tmp"
                            with temp_path.open("wb") as f:
                                f.write(raw_email)
                            temp_path.rename(eml_path)

                        store.index[content_hash] = {
                            "message_id": email_data.get("Message-ID", ""),
                            "subject": email_data.get("Subject", ""),
                            "from": email_data.get("From", ""),
                            "date": email_data.get("Date", ""),
                            "internaldate": internaldate,
                            "history": [{"folder": folder, "uid": uid}],
                        }
                        store.save_index()
                        new_count += 1
                        log(f"Fetched: {safe_str(email_data.get('Subject', '(no subject)')[:50], allow_newlines=False)}", Verbosity.DEBUG)
                print(f"\r    {i}/{len(uids)}", end="", flush=True)
            if uids:
                print()

        return server_state, new_count
    finally:
        mail.logout()


def sync_emails(account: MailConnectionInfos, auto_apply=False):
    """Sync local state with remote: fetch new emails, then detect deletions and moves with user review."""
    with Store(account.local_store_path) as store:
        server_state, new_count = _fetch_all_emails(account, store)
        _sync_apply(account, store, server_state, new_count, auto_apply)


def _sync_apply(account, store, server_state, new_count, auto_apply):
    if new_count:
        log(f"  Fetched {new_count} new email(s)", Verbosity.INFO)

    changelog = []
    for content_hash, entry in store.index.items():
        subj = safe_str(entry.get("subject", "(no subject)")[:50], allow_newlines=False)
        if content_hash not in server_state:
            if not entry.get("deleted"):
                changelog.append(("D", content_hash, subj, entry))
        else:
            current_folders = {loc["folder"] for loc in server_state[content_hash]}
            previous_folders = {h["folder"] for h in entry.get("history", []) if not h.get("removed")}
            new_folders = current_folders - previous_folders
            removed_folders = previous_folders - current_folders
            if new_folders or removed_folders:
                prev = ", ".join(safe_str(f, allow_newlines=False) for f in sorted(removed_folders)) if removed_folders else ""
                curr = ", ".join(safe_str(f, allow_newlines=False) for f in sorted(new_folders)) if new_folders else ""
                desc = f"{prev} -> {curr}" if prev and curr else (f"-> {curr}" if curr else f"{prev} -> (removed)")
                changelog.append(("M", content_hash, f"{subj}  ({desc})", entry))

    if not changelog:
        log(f"\nSync complete for {account.name}: {new_count} new, no server-side changes detected.", Verbosity.INFO)
        return

    try:
        term_width = os.get_terminal_size().columns
    except (ValueError, OSError):
        term_width = 80

    deletions = [c for c in changelog if c[0] == "D"]
    moves = [c for c in changelog if c[0] == "M"]

    print(f"\n{'─' * term_width}")
    print(f"  {account.name} — {new_count} new, {len(deletions)} deletion(s), {len(moves)} move(s) detected")
    print(f"{'─' * term_width}")
    for kind, _hash, desc, _entry in changelog:
        tag = f"{Color.RED.value}[D]{Color.WHITE.value}" if kind == "D" else f"{Color.PURP.value}[M]{Color.WHITE.value}"
        print(f"  {tag}  {desc}")
    print(f"{'─' * term_width}")

    if auto_apply:
        apply = True
    else:
        try:
            cmd = input("  Apply these changes to local index? [y/n] ").strip().lower()
        except EOFError:
            cmd = "n"
        apply = cmd in ("y", "yes")

    if not apply:
        log("  Server-side changes discarded (newly fetched emails are still saved).", Verbosity.INFO)
        store.save_index()
        return

    for kind, content_hash, _desc, entry in changelog:
        if kind == "D":
            entry["deleted"] = True
        elif kind == "M":
            current_folders = {loc["folder"] for loc in server_state[content_hash]}
            for loc in server_state[content_hash]:
                folder_names = [h["folder"] for h in entry.get("history", [])]
                if loc["folder"] not in folder_names:
                    entry.setdefault("history", []).append(loc)
            for h in entry.get("history", []):
                if h["folder"] not in current_folders:
                    h["removed"] = True

    store.save_index()
    log(f"  Applied: {len(deletions)} deletion(s), {len(moves)} move(s).", Verbosity.INFO)




def format_date(raw_date):
    try:
        return parsedate_to_datetime(raw_date).strftime("%Y-%m-%d:%H-%M-%S%z")
    except Exception:
        return safe_str(raw_date or "", allow_newlines=False)


@raise_smexception_on_connection_error
def send_email(account_config, recipients, subject, body, attachment_paths=None):
    sender_email = account_config.username
    message = MIMEMultipart()
    for k, v in {"From": sender_email, "To": ", ".join(recipients), "Subject": subject}.items():
        message[k] = v
    message.attach(MIMEText(body, "plain"))
    if attachment_paths:
        for file_path in attachment_paths:
            try:
                with Path(file_path).open("rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                filename = Path(file_path).name
                part.add_header("Content-Disposition", f"attachment; filename= {filename}")
                message.attach(part)

            except Exception as e:
                raise SMException(f"Error attaching file {file_path}: {str(e)}") from e

    try:
        ssl_context = make_pinned_ssl_context(
            account_config.pinned_smtp_certificate_sha256, cafile=account_config.ssl_cafile
        )
    except Exception as e:
        raise SMException(f"Verified TLS Error: {e}") from e

    try:
        server = SMTP(account_config.smtp_ssl_host, account_config.smtp_ssl_port)
        server.starttls(context=ssl_context)
        server.login(sender_email, account_config.password)
        text = message.as_string()
        server.sendmail(sender_email, recipients, text)
        log("Email sent successfully!", Verbosity.INFO)
    except SMTPAuthenticationError as exc:
        raise SMException(f"Auth error:\n{str(exc)}") from exc
    except Exception as exc:
        raise SMException(f"Error sending email: {str(exc)}") from exc
    finally:
        try:
            server.quit()
        except Exception:
            pass


def kiss_extract_text_from_eml(eml_path):
    """Naive text extraction: prefers text/plain, falls back to tag-stripped HTML.
    HTML handling is intentionally dumb (no entity decoding, no style/script removal) — good enough until it isn't."""
    with Path(eml_path).open("rb") as f:
        msg = message_from_bytes(f.read())
    text_parts = []
    html_parts = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                text_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    if text_parts:
        return "\n".join(text_parts)
    if html_parts:
        html = "\n".join(html_parts)
        html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<[^>]+>", "", html)
        return html
    return "(no text content)"


def read_emails(account: MailConnectionInfos):
    with Store(account.local_store_path) as store:
        _read_emails_ui(account, store)


def _read_emails_ui(account, store):
    if not store.index:
        raise SMException(f"No emails found for account {account.name}. Run sync first.")

    entries = [(h, e) for h, e in store.index.items() if not e.get("deleted")]
    entries.sort(key=lambda x: x[1].get("date", ""), reverse=True)
    if not entries:
        raise SMException(f"No non-deleted emails found for account {account.name}.")

    page_size = 20
    page = 0
    total_pages = (len(entries) + page_size - 1) // page_size

    try:
        term_width = os.get_terminal_size().columns
    except (ValueError, OSError):
        term_width = 80

    while True:
        start = page * page_size
        end = min(start + page_size, len(entries))
        page_entries = entries[start:end]

        print(f"\n{'─' * term_width}")
        print(f"  {account.name} — Page {page + 1}/{total_pages} ({len(entries)} emails)")
        print(f"{'─' * term_width}")

        for i, (_content_hash, entry) in enumerate(page_entries):
            num = start + i + 1
            frm = safe_str(entry.get("from", "")[:30], allow_newlines=False)
            date = format_date(entry.get("date", ""))
            subj = safe_str(entry.get("subject", "(no subject)"), allow_newlines=False)
            prefix = f"  {num:>4}  {frm:<30}  {date:<24}  "
            max_subj = term_width - len(prefix) - 1
            if max_subj > 0 and len(subj) > max_subj:
                subj = subj[: max_subj - 1] + "…"
            print(f"{prefix}{subj}")

        print(f"{'─' * term_width}")
        print("  [number] read  |  [n]ext  [p]rev  [q]uit")

        try:
            cmd = input("\n> ").strip().lower()
        except EOFError:
            break

        if cmd == "q":
            break
        elif cmd == "n":
            if page < total_pages - 1:
                page += 1
        elif cmd == "p":
            if page > 0:
                page -= 1
        elif cmd.isdigit():
            idx = int(cmd) - 1
            if 0 <= idx < len(entries):
                content_hash, entry = entries[idx]
                eml_path = store.mails_path / f"{content_hash}.eml"
                if not eml_path.exists():
                    print(f"  Email file not found: {eml_path}")
                    continue

                print(f"\n{'═' * term_width}")
                print(f"  From:    {safe_str(entry.get('from', ''), allow_newlines=False)}")
                print(f"  Date:    {format_date(entry.get('date', ''))}")
                print(f"  Subject: {safe_str(entry.get('subject', ''), allow_newlines=False)}")
                print(f"{'═' * term_width}")
                print(safe_str(kiss_extract_text_from_eml(eml_path), allow_newlines=True))
                print(f"{'═' * term_width}")
                print("  [b]ack to list  [q]uit")

                try:
                    cmd2 = input("\n> ").strip().lower()
                except EOFError:
                    break
                if cmd2 == "q":
                    break
            else:
                print(f"  Invalid number. Enter 1-{len(entries)}")
        else:
            print("  Unknown command.")


def usage(wrong_config=False, wrong_command=False):
    output_lines = [
        "sm - Simple Mail client",
        "───────────────────────",
        """~/.config/sm/config.json ──➤ {"accounts": [ACCOUNT_INFOS, ACCOUNT_INFOS, ...], ...}""",
        '  - optional: "default_account_for_send": "account_name"',
        '  - optional: "ssl_cafile": "/path/to/ca-bundle.crt"  (global default)',
        "  - ACCOUNT_INFOS = {",
        '    "name": "XX"',
        '    "imap_ssl_host": "XX"',
        '    "imap_ssl_port": 993',
        '    "username": "XX"',
        '    "password": "XX"',
        '    "pinned_imap_certificate_sha256": "XX"',
        '    "smtp_ssl_host": "XX"',
        '    "smtp_ssl_port": 587',
        '    "pinned_smtp_certificate_sha256": "XX"',
        '    "local_store_path": "XX"',
        '    "ssl_cafile": "/optional/override"  (overrides global)',
        "───────────────────────",
        "- sm send recipient=a@b.com [recipient=c@d.com ...] subject=title body=something [account=name] [file=path]",
        "- sm sync [account=name] [yes] [verbose=0|1|2]      ──➤ fetch new + review deletions/moves",
        "- sm read [account=name]                             ──➤ read emails in terminal",
        "───────────────────────",
        "  verbose= accepts 0/1/2 or error/info/debug (applies to all commands)",
        "You need to generate an app specific password for gmail or other mail clients",
    ]
    red_indexes = (list(range(2, 18)) if wrong_config else []) + ([19] if wrong_command else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["send", "sync", "read"]:
        return None
    remaining = [v for v in argv[2:] if not v.startswith("verbose=")]
    verbose_args = [v for v in argv[2:] if v.startswith("verbose=")]
    if verbose_args:
        val = verbose_args[-1].split("=", 1)[1].lower()
        mapping = {"0": "ERROR", "1": "INFO", "2": "DEBUG", "error": "ERROR", "info": "INFO", "debug": "DEBUG"}
        if val not in mapping:
            raise SMException(f"Invalid verbose level: {val} (use 0/1/2 or error/info/debug)")
        global _verbosity
        _verbosity = Verbosity[mapping[val]]
    if argv[1] == "sync":
        account = next((v[v.index("=") + 1 :] for v in remaining if v.startswith("account=")), None)
        auto_apply = "yes" in remaining
        invalid = [v for v in remaining if not v.startswith("account=") and v != "yes"]
        if invalid:
            raise SMException(f"Invalid options for sync: {'  ;  '.join(invalid)}")
        return {"action": "sync", "account": account, "auto_apply": auto_apply}
    if argv[1] == "read":
        account = next((v[v.index("=") + 1 :] for v in remaining if v.startswith("account=")), None)
        invalid = [v for v in remaining if not v.startswith("account=")]
        if invalid:
            raise SMException(f"Invalid options for read: {'  ;  '.join(invalid)}")
        return {"action": "read", "account": account}
    # send
    allowed_opts = ["recipient", "subject", "body", "file", "account"]
    mandatory_opts = ["subject", "body"]
    invalid_options = [v for v in remaining if all(not v.startswith(f"{o}=") for o in allowed_opts)]
    if invalid_options:
        raise SMException(f"Invalid options for send: {'  ;  '.join(invalid_options)}")
    single_opts = ("subject=", "body=", "account=")
    opts = {v[: v.index("=")]: v[v.index("=") + 1 :] for v in remaining if v.startswith(single_opts)}
    missing_options = [v for v in mandatory_opts if v not in opts]
    if missing_options:
        raise SMException(f"Missing options for send: {'  ;  '.join(missing_options)}")
    opts["recipients"] = [v[v.index("=") + 1 :] for v in remaining if v.startswith("recipient=")]
    if not opts["recipients"]:
        raise SMException("Missing options for send: recipient")
    opts["files"] = [v[v.index("=") + 1 :] for v in remaining if v.startswith("file=")]
    opts.setdefault("account", None)
    return {**opts, "action": "send"}


def resolve_accounts(mail_connections_infos, account_name):
    if account_name:
        accounts = [m for m in mail_connections_infos if m.name == account_name]
        if not accounts:
            raise SMException(f"Account named {account_name} not found")
        return accounts
    return list(mail_connections_infos)


def main():
    try:
        with CONFIG_PATH.open() as f:
            config = loads(f.read())
    except Exception:
        return usage(wrong_config=True)
    if not isinstance(config, dict) or not isinstance(config.get("accounts"), list):
        return usage(wrong_config=True)
    try:
        mail_connections_infos = [MailConnectionInfos.from_dict(s) for s in config["accounts"]]
    except Exception:
        return usage(wrong_config=True)
    global_ssl_cafile = config.get("ssl_cafile")
    for account in mail_connections_infos:
        if account.ssl_cafile is None:
            account.ssl_cafile = global_ssl_cafile
    account_names = [m.name for m in mail_connections_infos]
    if len(account_names) != len(set(account_names)):
        raise SMException("Duplicate account names in config")
    args = consume_args()
    if not args:
        return usage()
    if args["action"] == "send":
        account_name = args["account"] or config.get("default_account_for_send")
        if not account_name:
            raise SMException("No account specified and no default_account_for_send in config")
        send_email(
            resolve_accounts(mail_connections_infos, account_name)[0],
            args["recipients"], args["subject"], args["body"], args["files"],
        )
    elif args["action"] == "sync":
        for account in resolve_accounts(mail_connections_infos, args["account"]):
            sync_emails(account, auto_apply=args["auto_apply"])
    elif args["action"] == "read":
        accounts = resolve_accounts(mail_connections_infos, args["account"])
        if len(accounts) == 1:
            read_emails(accounts[0])
        else:
            names = ", ".join(m.name for m in accounts)
            raise SMException(f"Multiple accounts configured. Specify one with account=name\nAvailable: {names}")
    else:
        return usage()


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(-2)
    except SMException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
