#!/usr/bin/env python

"""
sm - Simple Mail client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.

Possible improvements (where to start if sync feels slow):
- Batched FETCH (UID FETCH 1:100 ...) instead of one body at a time — biggest single win on initial sync.
- Message-ID prefetch on UIDVALIDITY mismatch to skip re-downloading bodies we already have on disk.
- Other ideas: IDLE (push), COMPRESS=DEFLATE, CONDSTORE (flag changes), STATUS probe before SELECT, lazy body fetch.
"""

import base64
import os
import re
from collections import namedtuple
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from email import encoders, message_from_bytes
from email.header import decode_header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from enum import Enum
from hashlib import sha256
from html import unescape
from imaplib import IMAP4_SSL
from json import JSONDecodeError, dumps, loads
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
from sys import stdin as sys_stdin
from termios import TCSADRAIN, tcgetattr, tcsetattr
from tty import setraw
from unicodedata import east_asian_width
from urllib.error import HTTPError

CONFIG_PATH = Path.home() / ".config" / "sm" / "config.json"
LOCK_PATH = Path.home() / ".config" / "sm" / ".lock"

SYNC_BATCH_SIZE = 50  # UIDs per FETCH — trades round-trips for response memory peak.
SYNC_BATCH_BYTES = 50 * 1024 * 1024  # Max bytes per batched FETCH response. Cap on peak memory.

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])

Verbosity = Enum("Verbosity", [("ERROR", 0), ("INFO", 1), ("DEBUG", 2)])


@dataclass
class Param:
    verbosity: Verbosity = Verbosity.ERROR


@dataclass
class ErrorEvent:
    kind: str  # "parse_list", "select_failed", "select_error", ...
    detail: str  # human-readable, sanitized
    raw: bytes = None  # the original bytes/repr if useful for debug


@dataclass
class ReadUIState:
    """Session state for the read UI. Lives inside `_read_emails_ui`; not persisted.
    `offset` is the top visible row — viewport follows the cursor minimally (only scrolls
    when the cursor would go off-screen). `page_size` is recomputed from terminal height
    each frame. `find_mode` is the editing sub-state: when True, keystrokes feed the
    find editor and the bottom row shows the live prompt. `enabled_folders` is None when
    no folder filter is active (default, show all live entries); a set (including the
    empty set) means the filter is on — empty set is a deliberate "show nothing" state,
    not the same as no filter. `read_overrides` is reserved for the local read/unread
    feature (pass 4)."""

    cursor: int = 0
    offset: int = 0
    page_size: int = 20
    digit_buffer: str = ""
    find_query: str = ""
    find_mode: bool = False
    # Active preset selection — a string tag, not a resolved set. "[none]" = no filter,
    # "[custom]" = use folders_selected_in_custom, anything else = a config preset name.
    # We store the tag (intent) instead of the folder set so editing a preset's folders
    # in config.json auto-applies on next sm read. Resolution happens via _resolve_filter
    # against the in-memory presets dict (loaded once at startup, not re-read per frame).
    selection_current: str = "[none]"
    # The [custom] preset's folder set — preserved across modal sessions and runs.
    # None until the user has actually edited folders.
    folders_selected_in_custom: set | None = None
    # Recovery snapshot for the case where selection_current names a config preset that
    # has been deleted since last save. Treated as a one-off [custom] in that case so
    # the user doesn't lose their filter to a config drift.
    last_resolved: set | None = None
    # Diagnostic toggle for the list's date column. False = server INTERNALDATE (the
    # sort key — matches the visible order); True = the Date: header (sender-supplied,
    # often wrong). `d` toggles. Per-session; not persisted.
    header_date: bool = False


@dataclass
class Context:
    """Per-run shared state. `param` = static knobs; `errors` = events accumulated during execution."""

    param: Param = field(default_factory=Param)
    errors: list = field(default_factory=list)

    def log(self, msg, level=Verbosity.INFO):
        if level.value <= self.param.verbosity.value:
            print(msg)

    def record_error(self, kind, detail, raw=None):
        self.errors.append(ErrorEvent(kind=kind, detail=detail, raw=raw))


SAFE_PRINT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" " -.,;:!?/\\@#$%&*()[]{}=+_'\"<>~`^|" "\t\n\r"
)


def safe_str(text, allow_newlines=True):
    allowed = SAFE_PRINT_CHARS if allow_newlines else SAFE_PRINT_CHARS - {"\n", "\r"}
    return "".join(c if c in allowed else "\ufffd" for c in str(text))


def decoded_header(msg, name, default=""):
    """Return msg[name] as a plain decoded str, never an email.header.Header.
    Handles RFC 2047 encoded-words and raw 8-bit bytes from non-conforming senders
    (tries the declared charset, then UTF-8, then latin-1 as a last resort)."""
    raw = msg.get(name)
    if raw is None:
        return default
    try:
        out = []
        for chunk, charset in decode_header(raw):
            if isinstance(chunk, bytes):
                for enc in (charset, "utf-8", "latin-1"):
                    if not enc:
                        continue
                    try:
                        chunk = chunk.decode(enc)
                        break
                    except (UnicodeDecodeError, LookupError):
                        continue
            out.append(chunk)
        return "".join(out)
    except Exception:
        return str(raw)


def parse_size_response(data):
    """Parse an imaplib FETCH (RFC822.SIZE) response into ({uid: size_bytes}, [error_details]).

    Size-only responses don't include literals, so each per-message line arrives as plain bytes
    (no tuple). Defensive against tuples just in case some server emits them. Entries that don't
    match the expected shape are reported in the errors list rather than silently dropped."""
    sizes = {}
    errors = []
    for part in data:
        if isinstance(part, tuple):
            part = part[0]
        if not isinstance(part, bytes):
            errors.append(f"non-bytes entry: {type(part).__name__}")
            continue
        text = part.decode("ascii", errors="replace")
        uid_match = re.search(r"\bUID (\d+)", text)
        size_match = re.search(r"\bRFC822\.SIZE (\d+)", text)
        if uid_match and size_match:
            sizes[int(uid_match.group(1))] = int(size_match.group(1))
        else:
            errors.append(f"line missing UID or RFC822.SIZE: {text[:80]!r}")
    return sizes, errors


def pack_fetch_batches(to_fetch, sizes, max_count, max_bytes):
    """Greedy-pack UIDs into batches respecting both count and byte caps.
    A single message larger than max_bytes is fetched alone in its own batch
    (we still need it; nothing else gets to ride along). Missing sizes count as 0,
    so byte cap silently degrades to count-only when the size pre-flight is unavailable."""
    batch = []
    batch_bytes = 0
    for uid in to_fetch:
        size = sizes.get(uid, 0)
        if batch and (len(batch) >= max_count or batch_bytes + size > max_bytes):
            yield batch
            batch = []
            batch_bytes = 0
        batch.append(uid)
        batch_bytes += size
    if batch:
        yield batch


def _extract_internaldate(s):
    """Return the INTERNALDATE quoted value from an IMAP FETCH fragment, or '' if absent."""
    idx = s.find('INTERNALDATE "')
    if idx < 0:
        return ""
    start = idx + 14
    end = s.find('"', start)
    return s[start:end] if end > start else ""


def parse_fetch_response(data):
    """Parse an imaplib FETCH response into ([(uid, raw_email, internaldate), ...], [error_details]).

    `data` is the second element of mail.uid("FETCH", ...) — a list with one (header_bytes, body_bytes)
    tuple per message plus various non-tuple parts. Three shapes of non-tuple part are normal:
      - b')'                         — per-message terminator when all fields fit before the literal
      - b' INTERNALDATE "..." )'     — trailer when the server puts fields AFTER the body literal
                                       (Gmail does this with `(RFC822 INTERNALDATE)`); patched onto
                                       the immediately preceding result.
      - b'<seq> (UID <n> FLAGS ...)' — untagged FETCH notification for a flag change on some other
                                       message during our batch; no body, so no literal, so no tuple.
                                       Ignored — we don't track flags locally.
    Anything else that doesn't yield a UID is reported in the errors list."""
    results = []
    errors = []
    for part in data:
        if isinstance(part, tuple):
            header_bytes, body = part[0], part[1]
            if isinstance(header_bytes, bytes):
                header = header_bytes.decode("ascii", errors="replace")
            else:
                header = str(header_bytes)
            uid_match = re.search(r"\bUID (\d+)", header)
            if not uid_match:
                errors.append(f"tuple missing UID: {header[:80]!r}")
                continue
            uid = int(uid_match.group(1))
            internaldate = _extract_internaldate(header)
            if not internaldate and 'INTERNALDATE "' in header:
                errors.append(f"header for UID {uid} claims INTERNALDATE but extraction failed: {header[:80]!r}")
            results.append((uid, body, internaldate))
            continue
        text = part.decode("ascii", errors="replace") if isinstance(part, bytes) else str(part)
        stripped = text.strip()
        if stripped == ")":
            continue
        # Untagged FETCH flag notification — no literal, complete in one bytes object.
        if re.match(r"^\d+ \(UID \d+", stripped):
            continue
        # Trailer of the previous literal tuple: backfill INTERNALDATE if we didn't get it from the header.
        # Gates match the field's opening delimiter (quote / paren), not just the keyword, so a custom
        # IMAP keyword named "INTERNALDATE" or "FLAGS" can't collide with our trailer recognition.
        if results and stripped.endswith(")") and ('INTERNALDATE "' in stripped or "FLAGS (" in stripped):
            if 'INTERNALDATE "' in stripped:
                internaldate = _extract_internaldate(text)
                if internaldate:
                    if not results[-1][2]:
                        uid, body, _ = results[-1]
                        results[-1] = (uid, body, internaldate)
                    continue
                errors.append(
                    f"trailer for UID {results[-1][0]} claims INTERNALDATE but extraction failed: {text[:80]!r}"
                )
            elif "FLAGS (" in stripped:
                continue  # FLAGS-only trailer; we don't track flags locally
        else:
            errors.append(f"unexpected non-tuple entry: {part!r}"[:120])
    # We always request INTERNALDATE alongside RFC822, so a result with no date is a parser miss
    # (unknown trailer shape, mangled header, etc.) — surface it so silent date-loss can't recur.
    for uid, _body, internaldate in results:
        if not internaldate:
            errors.append(f"missing INTERNALDATE for UID {uid}")
    return results, errors


def parse_internaldate_only(data):
    """Parse a FETCH `(INTERNALDATE)`-only response into ([(uid, internaldate), ...], [errors]).

    Simpler shape than parse_fetch_response: no RFC822 body literal means no header+trailer
    split — each response part is a single bytes/str fragment that fully describes one UID.
    Used by `resync_emails`, where we only need INTERNALDATE and want to skip body bandwidth."""
    results = []
    errors = []
    for part in data:
        if part is None:
            errors.append("non-bytes part in INTERNALDATE response: None")
            continue
        if isinstance(part, (bytes, bytearray)):
            text = part.decode("ascii", errors="replace")
        else:
            text = str(part)
        if not text.strip() or text.strip() == ")":
            continue
        uid_match = re.search(r"\bUID (\d+)", text)
        if not uid_match:
            errors.append(f"INTERNALDATE-only part missing UID: {text[:80]!r}")
            continue
        uid = int(uid_match.group(1))
        internal = _extract_internaldate(text)
        if not internal:
            errors.append(f"INTERNALDATE-only part missing INTERNALDATE for UID {uid}: {text[:80]!r}")
            continue
        results.append((uid, internal))
    return results, errors


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


@dataclass
class StoreSnapshot:
    """Lock-free read-only view of the on-disk store. Returned by `Store.load_snapshot`.

    .eml files are content-addressed (sha256) and write-once, so reading them lazily off
    the snapshot is safe even if a concurrent sync is updating index.json — the worst
    case is staleness (missing newer messages), never inconsistency.

    Do not mutate. Persistence requires `with Store(...) as store: ...` instead."""

    messages: dict
    folder_states: dict
    mails_path: Path


class Store:
    """Local persistence for synced email — owns the lock, the index, and the .eml files.

    On disk (under store_path):
      mails/         one .eml per unique message, named <sha256>.eml (the content hash dedups
                     the same body appearing in multiple folders).
      index.json     combined message index + folder metadata. Shape:
                       {"messages": {<sha256>: entry, ...},
                        "folders":  {<folder_name>: state, ...}}

    In memory (populated on context entry):
      self.messages       {sha256_hash: entry}. Same body in multiple folders is one entry;
                          entry["history"] lists every (folder, uid) we've seen it at.
      self.folder_states  {folder_name: {"uidvalidity": int, ...}}, per-folder protocol
                          bookkeeping. See RFC 3501 §2.3.1.1 for UIDVALIDITY semantics.

    Lifecycle: `with Store(path) as store:` acquires a single-instance lock and loads from
    disk. Mutate `store.messages` / `store.folder_states` freely, then `store.save()` to
    persist (atomic temp + rename). Exiting the context releases the lock.

    For read-only flows (reader UI, demos, reporting), use `Store.load_snapshot(path)` —
    it returns a `StoreSnapshot` without acquiring the lock, so it doesn't block syncs.
    """

    _active = False

    def __init__(self, local_store_path):
        self.store_path = Path(local_store_path)
        self.mails_path = self.store_path / "mails"
        self.messages = None  # {sha256_hash: entry}
        self.folder_states = None  # {folder_name: {"uidvalidity": int}} — see RFC 3501 §2.3.1.1

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
            data = self._load_index_file(self.store_path)
            self.messages = data.get("messages", {})
            self.folder_states = data.get("folders", {})
        except OSError as exc:
            LOCK_PATH.unlink()
            Store._active = False
            raise SMException(f"Failed to initialize local store at {self.store_path}: {exc}") from exc
        return self

    def __exit__(self, *exc):
        LOCK_PATH.unlink()
        Store._active = False

    @staticmethod
    def _load_index_file(store_path):
        path = store_path / "index.json"
        if not path.exists():
            return {}
        content = path.read_text()
        if not content.strip():
            return {}
        try:
            return loads(content)
        except JSONDecodeError as exc:
            raise SMException(
                f"index.json at {path} is corrupted ({exc.msg} at line {exc.lineno} col {exc.colno}). "
                f"Rename or remove the file and re-sync to recover."
            ) from exc

    @classmethod
    def load_snapshot(cls, local_store_path):
        """Read-only load with no lock acquired. See StoreSnapshot for the staleness contract."""
        store_path = Path(local_store_path)
        data = cls._load_index_file(store_path)
        return StoreSnapshot(
            messages=data.get("messages", {}),
            folder_states=data.get("folders", {}),
            mails_path=store_path / "mails",
        )

    def save(self):
        """Persist messages + folder_states to index.json (atomic temp + rename)."""
        if not Store._active:
            raise SMException("Cannot save outside of Store context")
        path = self.store_path / "index.json"
        temp_path = self.store_path / ".index.json.tmp"
        with temp_path.open("w") as f:
            f.write(dumps({"messages": self.messages, "folders": self.folder_states}, indent=2))
        temp_path.rename(path)


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
    # Optional: named folder filter presets shown in the read UI's folder menu, e.g.
    # {"business": ["Work", "Projects"], "personal": ["INBOX", "Family"]}. Pressing
    # space on a preset overwrites the folder ticks to that set.
    folder_presets: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict):
        valid = {f.name for f in fields(cls)}
        invalid = set(d.keys()) - valid
        if invalid:
            raise SMException(f"Wrong argument for account in config: {', '.join(invalid)}")
        return cls(**d)


def list_attachments(msg):
    """Return [(filename, content_bytes)] for every MIME part with a filename. 1-indexed by position."""
    out = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if not filename:
            continue
        content = part.get_payload(decode=True) or b""
        out.append((filename, content))
    return out


def save_attachment_bytes(content, dest_dir, suggested_name):
    """Write content to dest_dir/<sanitized_name>. mkdir -p dest_dir.
    Rename on collision (_1, _2, ...). Returns Path."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c in ALLOWED_NAME_CHARS else "_" for c in suggested_name) or "attachment"
    if safe_name.startswith("."):  # no hidden files in the destination — prefix with _, keep the original visible
        safe_name = "_" + safe_name
    if safe_name.strip("._") == "":  # all dots/underscores — would resolve to a directory or be visual noise
        safe_name = "attachment"
    target = dest_dir / safe_name
    if target.exists():
        stem, suffix = Path(safe_name).stem, Path(safe_name).suffix
        n = 1
        while (dest_dir / f"{stem}_{n}{suffix}").exists():
            n += 1
        target = dest_dir / f"{stem}_{n}{suffix}"
    target.write_bytes(content)
    return target


ListEntry = namedtuple("ListEntry", ["flags", "delim", "name", "name_for_select"])


# Per RFC 3501 §5.1.3, IMAP mailbox names are 7-bit ASCII (modified UTF-7).
# Explicit allowlist: every printable ASCII char except '"' and '\\' (would break SELECT quoting).
# Listed by hand so a reviewer can audit by eye — implicit ranges hide off-by-one bugs.
_SAFE_FOLDER_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !#$%&'()*+,-./:;<=>?@[]^_`{|}~"  # printable punctuation; '"' (0x22) and '\\' (0x5C) intentionally absent
)
_SAFE_FOLDER_BYTES = frozenset(ord(c) for c in _SAFE_FOLDER_CHARS)


def _is_safe_folder_name(name):
    """True if `name` is safe to interpolate into f'\"{name}\"' for IMAP commands."""
    return all(c in _SAFE_FOLDER_CHARS for c in name)


def decode_modified_utf7(b):
    """Decode RFC 3501 §5.1.3 modified UTF-7 bytes to a Python str.
    Modified base64 uses ',' in place of '/'; payload is unpadded; '&-' encodes a literal '&'.
    Falls back to ASCII-replace on malformed input rather than raising."""
    if not isinstance(b, (bytes, bytearray)):
        return ""
    out = []
    i, n = 0, len(b)
    while i < n:
        if b[i : i + 1] != b"&":
            out.append(b[i : i + 1].decode("ascii", "replace"))
            i += 1
            continue
        end = b.find(b"-", i + 1)
        if end == -1:
            out.append(b[i:].decode("ascii", "replace"))
            break
        payload = b[i + 1 : end]
        if not payload:
            out.append("&")
        else:
            std = payload.replace(b",", b"/")
            std += b"=" * ((4 - len(std) % 4) % 4)
            try:
                out.append(base64.b64decode(std, validate=True).decode("utf-16-be"))
            except Exception:
                out.append(b[i : end + 1].decode("ascii", "replace"))
        i = end + 1
    return "".join(out)


def parse_list_response(item, ctx=None):
    """Parse one IMAP LIST response item per RFC 3501 §7.2.2.

    Shape: (flags) delim mailbox-name
      - flags: \\-prefixed atoms separated by spaces
      - delim: NIL or "<char>" (char may be backslash-escaped)
      - mailbox-name: quoted, literal ({N}), or atom; modified UTF-7

    item: bytes (single line) or tuple of bytes (line carrying a literal continuation).
    ctx:  optional Context. If provided, every parse failure records an ErrorEvent
          (kind="parse_list", detail=specific reason, raw=<original bytes>).
    Returns ListEntry(flags, delim, name, name_for_select) or None if unparseable.
      flags           — frozenset[str], e.g. {"\\HasNoChildren"}
      delim           — single-char str, or None for NIL
      name            — modified-UTF-7-decoded human-readable str
      name_for_select — ASCII str safe to send back to the server (keeps modified UTF-7)
    """
    if isinstance(item, tuple):
        raw = b"".join(p for p in item if isinstance(p, (bytes, bytearray)))
    elif isinstance(item, (bytes, bytearray)):
        raw = bytes(item)
    else:
        raw = repr(item).encode("utf-8", "replace")  # preserve identity for the error event
    raw = raw.strip()

    def _fail(reason):
        if ctx is not None:
            ctx.record_error("parse_list", reason, raw=raw)
        return None

    if not isinstance(item, (bytes, bytearray, tuple)):
        return _fail("non-bytes/tuple input")

    n = len(raw)
    i = 0

    # 1) flag-list: '(' ... ')'
    if i >= n or raw[i : i + 1] != b"(":
        return _fail("no opening paren on flag list")
    i += 1
    flags_start = i
    depth = 1
    while i < n and depth > 0:
        c = raw[i : i + 1]
        if c == b"(":
            depth += 1
        elif c == b")":
            depth -= 1
        i += 1
    if depth != 0:
        return _fail("unterminated flag list")
    flags_bytes = raw[flags_start : i - 1]

    while i < n and raw[i : i + 1] in (b" ", b"\t"):
        i += 1

    # 2) delim: NIL or "<char>" with optional backslash escape
    if raw[i : i + 3] == b"NIL":
        delim = None
        i += 3
    elif raw[i : i + 1] == b'"':
        i += 1
        if i >= n:
            return _fail("truncated after opening quote on delimiter")
        if raw[i : i + 1] == b"\\":
            i += 1
            if i >= n:
                return _fail("truncated after backslash escape in delimiter")
        delim = raw[i : i + 1].decode("ascii", "replace")
        i += 1
        if i >= n or raw[i : i + 1] != b'"':
            return _fail("missing closing quote on delimiter")
        i += 1
    else:
        return _fail("expected delimiter (NIL or quoted char)")

    while i < n and raw[i : i + 1] in (b" ", b"\t"):
        i += 1
    if i >= n:
        return _fail("missing mailbox name")

    # 3) mailbox-name: quoted, literal, or atom
    if raw[i : i + 1] == b'"':
        i += 1
        chars = bytearray()
        while i < n and raw[i : i + 1] != b'"':
            if raw[i : i + 1] == b"\\" and i + 1 < n:
                chars.append(raw[i + 1])
                i += 2
            else:
                chars.append(raw[i])
                i += 1
        if i >= n:
            return _fail("unterminated quoted mailbox name")
        name_bytes = bytes(chars)
    elif raw[i : i + 1] == b"{":
        end = raw.find(b"}", i)
        if end == -1:
            return _fail("malformed literal length marker (no closing brace)")
        try:
            count = int(raw[i + 1 : end])
        except ValueError:
            return _fail("non-numeric literal length")
        j = end + 1
        if raw[j : j + 2] == b"\r\n":
            j += 2
        elif raw[j : j + 1] in (b"\r", b"\n"):
            j += 1
        if j + count > n:
            return _fail("literal length exceeds available bytes")
        name_bytes = raw[j : j + count]
    else:
        start = i
        while i < n and raw[i : i + 1] not in (b" ", b"\t", b"\r", b"\n"):
            i += 1
        if i == start:
            return _fail("empty atom mailbox name")
        name_bytes = raw[start:i]

    # Defense in depth: also rechecked at the SELECT call site in _fetch_all_emails.
    for byte in name_bytes:
        if byte not in _SAFE_FOLDER_BYTES:
            return _fail(f"folder name contains disallowed byte 0x{byte:02x}")

    return ListEntry(
        flags=frozenset(flags_bytes.decode("ascii", "replace").split()),
        delim=delim,
        name=decode_modified_utf7(name_bytes),
        name_for_select=name_bytes.decode("ascii", "replace"),
    )


def _invalidate_cache_for_folder(known_uids, folder):
    """Drop every (folder, uid) -> hash entry for `folder`. Returns the number of removed entries.
    Used when UIDVALIDITY changes — old UIDs no longer point to the messages we cached against them."""
    keys = [k for k in known_uids if k[0] == folder]
    for k in keys:
        del known_uids[k]
    return len(keys)


def _read_uidvalidity(mail):
    """Return the UIDVALIDITY of the currently-selected folder as an int, or None if absent/malformed.
    imaplib stores UIDVALIDITY in its untagged-response cache after SELECT."""
    typ, data = mail.response("UIDVALIDITY")
    if not data or not data[0]:
        return None
    try:
        return int(data[0])
    except (ValueError, TypeError):
        return None


@raise_smexception_on_connection_error
def _fetch_all_emails(account: MailConnectionInfos, store: Store, ctx: Context):
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
            entry = parse_list_response(item, ctx)
            if entry is None:
                continue  # specific reason already recorded on ctx by parse_list_response
            folders.append(entry.name_for_select)  # raw form: stable identity for SELECT and index storage
        if not folders:
            raise SMException(f"No folders found. Raw response: {folder_data[:3]}...")

        # Build reverse lookup: (folder, uid) -> content_hash from existing index.
        # UIDVALIDITY (per-folder, returned on SELECT) gates this cache: if it changes, the
        # (folder, uid) pairs we cached against the old UIDVALIDITY no longer correspond to the
        # same messages on the server. We invalidate the cache for that folder when it happens.
        known_uids = {}
        for content_hash, entry in store.messages.items():
            for h in entry.get("history", []):
                known_uids[(h["folder"], h["uid"])] = content_hash

        server_state = {}
        new_count = 0

        for folder in folders:
            # Defense in depth: also gated at parse_list_response. If this fires, something bypassed the parser.
            safe_folder = safe_str(folder, allow_newlines=False)
            if not _is_safe_folder_name(folder):
                ctx.log(f"Skipping unsafe folder name: {safe_folder}", Verbosity.DEBUG)
                ctx.record_error(
                    "unsafe_folder_name",
                    f"folder {folder!r} contains disallowed bytes; refusing to SELECT",
                )
                continue
            try:
                status, messages = mail.select(f'"{folder}"')
                if status != "OK":
                    ctx.log(f"Skipping folder (select failed): {safe_folder}", Verbosity.DEBUG)
                    ctx.record_error("select_failed", f"SELECT returned {status} for folder {folder!r}")
                    continue
            except Exception as exc:
                ctx.log(f"Skipping folder: {safe_folder}", Verbosity.DEBUG)
                ctx.record_error("select_error", f"SELECT raised {type(exc).__name__} for folder {folder!r}: {exc}")
                continue

            # UIDVALIDITY check: if the server's value differs from what we stored, our cached
            # (folder, uid) mappings are stale — drop them so this folder gets fully re-fetched.
            # Content-hash dedup avoids rewriting .eml files we already have on disk.
            current_uidv = _read_uidvalidity(mail)
            stored_uidv = store.folder_states.get(folder, {}).get("uidvalidity")
            if current_uidv is not None and stored_uidv is not None and current_uidv != stored_uidv:
                removed = _invalidate_cache_for_folder(known_uids, folder)
                noun = "entry" if removed == 1 else "entries"
                ctx.log(
                    f"UIDVALIDITY changed for {safe_folder}: "
                    f"{stored_uidv} -> {current_uidv}; re-fetching {removed} cached {noun}",
                    Verbosity.INFO,
                )
                ctx.record_error(
                    "uidvalidity_changed",
                    f"folder {folder!r} UIDVALIDITY changed from {stored_uidv} to {current_uidv}; cache invalidated",
                )
            if current_uidv is not None:
                store.folder_states.setdefault(folder, {})["uidvalidity"] = current_uidv

            result, data = mail.uid("SEARCH", None, "ALL")
            if not data[0]:
                continue
            uids = [int(s) for s in data[0].split()]
            print(f"  {safe_str(folder, allow_newlines=False)}: {len(uids)} email(s)")

            # Partition UIDs into already-cached (skip) vs to-fetch (batched FETCH below).
            to_fetch = []
            done = 0
            for uid in uids:
                cached_hash = known_uids.get((folder, uid))
                if cached_hash and (store.mails_path / f"{cached_hash}.eml").exists():
                    server_state.setdefault(cached_hash, []).append({"folder": folder, "uid": uid})
                    done += 1
                else:
                    to_fetch.append(uid)
            if uids:
                print(f"\r    {done}/{len(uids)}", end="", flush=True)

            # Pre-flight size lookup so we can cap each batch by bytes (peak memory) as well as count.
            # Skipped when there's nothing to fetch — keeps no-op syncs free of extra round-trips.
            sizes = {}
            if to_fetch:
                size_set = ",".join(str(u) for u in to_fetch)
                _result, size_data = mail.uid("fetch", size_set, "(RFC822.SIZE)")
                sizes, size_parse_errors = parse_size_response(size_data)
                for detail in size_parse_errors:
                    ctx.record_error("size_parse_error", f"folder {folder!r}: {detail}")
                if len(sizes) < len(to_fetch):
                    # Missing sizes silently degrade the byte cap (treated as 0); surface it.
                    ctx.record_error(
                        "size_preflight_incomplete",
                        f"folder {folder!r}: requested sizes for {len(to_fetch)} UIDs, got {len(sizes)}",
                    )

            for batch in pack_fetch_batches(to_fetch, sizes, SYNC_BATCH_SIZE, SYNC_BATCH_BYTES):
                uid_set = ",".join(str(u) for u in batch)
                result, data = mail.uid("fetch", uid_set, "(RFC822 INTERNALDATE)")
                parsed, parse_errors = parse_fetch_response(data)
                for detail in parse_errors:
                    ctx.record_error("fetch_parse_error", f"folder {folder!r}: {detail}")
                if len(parsed) < len(batch):
                    # Missing messages self-heal next sync (still in to_fetch), but record so the user sees it.
                    got_uids = {u for u, _, _ in parsed}
                    missing = [u for u in batch if u not in got_uids]
                    preview = missing[:10]
                    suffix = "..." if len(missing) > 10 else ""
                    ctx.record_error(
                        "fetch_incomplete",
                        f"folder {folder!r}: requested {len(batch)} UIDs, got {len(parsed)} "
                        f"(missing: {preview}{suffix})",
                    )
                for uid, raw_email, internaldate in parsed:
                    content_hash = sha256(raw_email).hexdigest()
                    server_state.setdefault(content_hash, []).append({"folder": folder, "uid": uid})

                    # Ensure the .eml is on disk regardless of whether we already index this hash:
                    #   - new message:                    write
                    #   - indexed but file missing:       write (recovery from manual delete / partial run)
                    #   - orphan file not yet indexed:    paranoid hash check, adopt
                    #   - indexed and file present:       trust (no per-fetch hash check, expensive at scale)
                    eml_path = store.mails_path / f"{content_hash}.eml"
                    if eml_path.exists():
                        if content_hash not in store.messages:
                            with eml_path.open("rb") as f:
                                existing_hash = sha256(f.read()).hexdigest()
                            if existing_hash != content_hash:
                                raise SMException(
                                    f"Corruption detected: {eml_path} hash mismatch "
                                    f"(expected {content_hash}, got {existing_hash})"
                                )
                    else:
                        temp_path = store.mails_path / f".{content_hash}.eml.tmp"
                        with temp_path.open("wb") as f:
                            f.write(raw_email)
                        temp_path.rename(eml_path)

                    if content_hash in store.messages:
                        existing = store.messages[content_hash]
                        # `folder_names` must consider only LIVE history entries — a folder we
                        # previously left (entry has removed=True) should accept a fresh live
                        # entry on return, not be treated as "already there." This is the
                        # A → B → A case.
                        live = {h["folder"]: h for h in existing.get("history", []) if not h.get("removed")}
                        if folder not in live:
                            # New folder for this message OR resurrection of a previously-removed one.
                            existing.setdefault("history", []).append({"folder": folder, "uid": uid})
                        else:
                            # Folder is currently live. UID may have changed (UIDVALIDITY bump on
                            # a message that stayed in the folder); update it in place.
                            h = live[folder]
                            if h.get("uid") != uid:
                                h["uid"] = uid
                    else:
                        email_data = message_from_bytes(raw_email)
                        store.messages[content_hash] = {
                            "message_id": decoded_header(email_data, "Message-ID"),
                            "subject": decoded_header(email_data, "Subject"),
                            "from": decoded_header(email_data, "From"),
                            "date": decoded_header(email_data, "Date"),
                            "internaldate": internaldate,
                            "history": [{"folder": folder, "uid": uid}],
                        }
                        new_count += 1
                        subject_preview = safe_str(
                            decoded_header(email_data, "Subject", "(no subject)")[:50], allow_newlines=False
                        )
                        ctx.log(f"Fetched: {subject_preview}", Verbosity.DEBUG)
                    done += 1
                    print(f"\r    {done}/{len(uids)}", end="", flush=True)
                # Save once per batch — atomic; orphan adoption recovers a crash mid-batch.
                store.save()
            if uids:
                print()

        store.save()  # persist any folder_state updates that didn't trigger a per-message save
        return server_state, new_count
    finally:
        mail.logout()


def sync_emails(account: MailConnectionInfos, ctx: Context, auto_apply=False, max_silent_retries=2):
    """Sync local state with remote: fetch new emails, then detect deletions and moves with user review.

    On SMException, silently retry up to max_silent_retries times (transient network errors recover
    cleanly because saves are atomic — partial progress on disk is consistent and the next attempt
    resumes from there). After silent retries are exhausted, prompt the user `Retry? [y/N]`. Saying
    yes runs another batch of silent retries; saying no re-raises the last exception. Set
    max_silent_retries=0 for no retry at all (e.g., in tests, or to fail fast).

    Producer-only: appends to ctx.errors as things go wrong. The caller (e.g. main) decides when
    and how to render those — see _summarize_errors."""
    while True:
        last_exc = None
        for attempt in range(max_silent_retries + 1):
            try:
                with Store(account.local_store_path) as store:
                    server_state, new_count = _fetch_all_emails(account, store, ctx)
                    _sync_apply(account, store, server_state, new_count, auto_apply, ctx)
                return
            except SMException as exc:
                last_exc = exc
                if attempt < max_silent_retries:
                    ctx.log(
                        f"sync attempt {attempt + 1} failed: {exc}; retrying ({max_silent_retries - attempt} left)",
                        Verbosity.INFO,
                    )
        try:
            choice = (
                input(f"  sync failed after {max_silent_retries + 1} attempt(s): {last_exc}\n" f"  Retry? [y/N] ")
                .strip()
                .lower()
            )
        except EOFError:
            choice = "n"
        if choice not in ("y", "yes"):
            raise last_exc


def resync_internaldate(account: MailConnectionInfos, ctx: Context):
    """Backfill missing INTERNALDATE on live entries by re-fetching `(INTERNALDATE)`
    only — no body, ~50 bytes/msg vs ~50KB/msg, so this is cheap to run regularly.

    Conservative by design: only fills entries whose `internaldate` is empty. Never
    overwrites existing values (even unparseable ones). UIDVALIDITY mismatch on a
    folder = skip + record an error; the regular sync handles UIDVALIDITY changes,
    so the user should run `sm sync` then `sm resync-internaldate` again. Skips gone
    entries (all-history-removed) entirely — they aren't shown in the read UI, so
    refetching their INTERNALDATE would be wasted work. Producer-only: appends to
    ctx.errors; the caller renders them via _summarize_errors."""
    with Store(account.local_store_path) as store:
        # Group by folder so each SELECT amortizes over many fetches.
        # is_live filter guarantees there's at least one non-removed history entry,
        # so live[0] is always safe — no fallback or no-history edge case to handle.
        by_folder = {}
        for content_hash, entry in store.messages.items():
            if not is_live(entry) or entry.get("internaldate"):
                continue
            live = [h for h in entry["history"] if not h.get("removed")]
            h = live[0]
            by_folder.setdefault(h["folder"], []).append((h["uid"], content_hash))
        if not by_folder:
            print(f"  {account.name}: nothing to resync (all live entries have INTERNALDATE)")
            return

        ssl_context = make_pinned_ssl_context(account.pinned_imap_certificate_sha256, cafile=account.ssl_cafile)
        mail = IMAP4_SSL(account.imap_ssl_host, account.imap_ssl_port, ssl_context=ssl_context)
        mail.login(account.username, account.password)
        try:
            total_filled = 0
            for folder, items in by_folder.items():
                safe_folder = safe_str(folder, allow_newlines=False)
                # Defense in depth: also gated at parse_list_response. If we got here with
                # an unsafe folder name, something bypassed the parser — skip.
                if not _is_safe_folder_name(folder):
                    ctx.record_error(
                        "unsafe_folder_name",
                        f"folder {folder!r} contains disallowed bytes; refusing to SELECT (resync)",
                    )
                    continue
                try:
                    status, _msgs = mail.select(f'"{folder}"')
                    if status != "OK":
                        ctx.record_error("select_failed", f"resync SELECT returned {status} for folder {folder!r}")
                        continue
                except Exception as exc:
                    ctx.record_error(
                        "select_error",
                        f"resync SELECT raised {type(exc).__name__} for folder {folder!r}: {exc}",
                    )
                    continue

                # If UIDVALIDITY changed since last sync, our cached UIDs may not point to the
                # same messages anymore — sending a FETCH for them could backfill INTERNALDATE
                # from a different message entirely. Skip + record; the regular sync heals it.
                current_uidv = _read_uidvalidity(mail)
                stored_uidv = store.folder_states.get(folder, {}).get("uidvalidity")
                if current_uidv is not None and stored_uidv is not None and current_uidv != stored_uidv:
                    ctx.record_error(
                        "uidvalidity_changed",
                        f"resync skipping folder {folder!r}: UIDVALIDITY {stored_uidv} -> "
                        f"{current_uidv}; run sync first",
                    )
                    continue

                uid_to_hash = dict(items)
                uids = list(uid_to_hash.keys())
                noun = "entry" if len(uids) == 1 else "entries"
                print(f"  {safe_folder}: refetching INTERNALDATE for {len(uids)} {noun}")
                done = 0
                # Count-only batching — INTERNALDATE-only responses are tiny (~50 bytes/msg),
                # so peak memory is a non-issue. SYNC_BATCH_SIZE keeps round-trips reasonable.
                for i in range(0, len(uids), SYNC_BATCH_SIZE):
                    batch = uids[i : i + SYNC_BATCH_SIZE]
                    uid_set = ",".join(str(u) for u in batch)
                    _result, data = mail.uid("FETCH", uid_set, "(INTERNALDATE)")
                    parsed, parse_errors = parse_internaldate_only(data)
                    for detail in parse_errors:
                        ctx.record_error("resync_parse_error", f"folder {folder!r}: {detail}")
                    got = {u for u, _ in parsed}
                    missing = [u for u in batch if u not in got]
                    if missing:
                        preview = missing[:10]
                        suffix = "..." if len(missing) > 10 else ""
                        ctx.record_error(
                            "resync_fetch_incomplete",
                            f"folder {folder!r}: requested INTERNALDATE for {len(batch)} UIDs, "
                            f"got {len(parsed)} (missing: {preview}{suffix})",
                        )
                    for uid, internal in parsed:
                        ch = uid_to_hash.get(uid)
                        if ch:
                            store.messages[ch]["internaldate"] = internal
                            total_filled += 1
                    done += len(batch)
                    print(f"\r    {done}/{len(uids)}", end="", flush=True)
                store.save()
                if uids:
                    print()
            noun = "entry" if total_filled == 1 else "entries"
            print(f"  {account.name}: filled INTERNALDATE for {total_filled} {noun}")
        finally:
            mail.logout()


def is_live(entry):
    """True iff at least one history entry is still live (not marked removed).
    Empty history is treated as gone (defensive — entries are always created with one history item)."""
    return any(not h.get("removed") for h in entry.get("history", []))


def _entries_visible(all_entries, state, enabled_folders):
    """Apply session UI filters (folder set, find query) to the already-live entries list.
    Both filters compose with AND. `enabled_folders` is None when no folder filter is
    active; a set (including the empty set) when active — empty set is a deliberate
    "show nothing" state. Folder match requires a *live* history entry in an enabled
    folder, not just any history record — keeps removed-from-folder entries from
    re-appearing via the filter."""
    q = state.find_query.lower() if state.find_query else ""
    folders = enabled_folders
    out = []
    for h, e in all_entries:
        if folders is not None:
            if not any(hist["folder"] in folders and not hist.get("removed") for hist in e.get("history", [])):
                continue
        if q:
            subj = (e.get("subject") or "").lower()
            frm = (e.get("from") or "").lower()
            if q not in subj and q not in frm:
                continue
        out.append((h, e))
    return out


def _all_folders_from_entries(all_entries, presets=None):
    """Sorted union of every folder name in entry history plus every folder named by any
    config preset. Preset-mentioned folders that have no messages locally still show up
    in the filter menu so the user can opt into them — your earlier suggestion that we
    don't need a separate 'missing' UX state."""
    folders = set()
    for _h, e in all_entries:
        for hist in e.get("history", []):
            folders.add(hist["folder"])
    if presets:
        for preset_folders in presets.values():
            folders.update(preset_folders)
    return sorted(folders)


STATE_VERSION = 1


def _state_path(local_store_path):
    return Path(local_store_path) / "state.json"


def _resolve_filter(selection_current, folders_selected_in_custom, last_resolved, presets):
    """Turn a selection tag + auxiliary state into the actual folder filter set.
    None return = no filter (filter off). A set = filter on with those folders.

    `presets` is the in-memory dict from `account.folder_presets`, parsed once at sm
    startup — this function does no disk I/O.

    Resolution order: "[none]" → None, "[custom]" → user's custom set, named preset
    that's still in the presets dict → its current folders, named preset that's been
    deleted from config since the state was saved → last_resolved (so config drift
    doesn't silently lose the user's filter), nothing usable → None."""
    if selection_current == "[none]":
        return None
    if selection_current == "[custom]":
        return set(folders_selected_in_custom) if folders_selected_in_custom is not None else set()
    if selection_current in presets:
        return set(presets[selection_current])
    if last_resolved is not None:
        return set(last_resolved)
    return None


def _load_folder_state(local_store_path):
    """Return (selection_current, folders_selected_in_custom, last_resolved).
    selection_current is a string (defaults to "[none]"); the other two are sets or None.
    Missing or corrupt state.json → defaults."""
    path = _state_path(local_store_path)
    defaults = ("[none]", None, None)
    if not path.exists():
        return defaults
    try:
        data = loads(path.read_text())
    except (OSError, JSONDecodeError):
        return defaults
    sel = data.get("selection_current")
    if not isinstance(sel, str):
        sel = "[none]"

    def _as_set(value):
        return set(value) if isinstance(value, list) else None

    return sel, _as_set(data.get("folders_selected_in_custom")), _as_set(data.get("last_resolved"))


def _save_folder_state(local_store_path, selection_current, folders_selected_in_custom, last_resolved):
    """Persist via atomic temp + rename. Sets serialize as sorted lists; None as json null."""
    path = _state_path(local_store_path)
    temp_path = path.with_name(".state.json.tmp")
    payload = {
        "version": STATE_VERSION,
        "selection_current": selection_current,
        "folders_selected_in_custom": sorted(folders_selected_in_custom)
        if folders_selected_in_custom is not None
        else None,
        "last_resolved": sorted(last_resolved) if last_resolved is not None else None,
    }
    temp_path.write_text(dumps(payload, indent=2))
    temp_path.rename(path)


def is_gone(entry):
    """True iff the message has no live folder location anywhere we've synced.
    Equivalent to `not is_live(entry)`. See `_sync_apply` for the eventual-consistency contract:
    "gone" is a snapshot judgment over the synced folder set at the time of the diff."""
    return not is_live(entry)


def _sync_apply(account, store, server_state, new_count, auto_apply, ctx):
    """Diff the in-memory `server_state` (just produced by `_fetch_all_emails`) against
    `store.messages`. Surface deletions and moves to the user (or apply silently if `auto_apply`).

    Eventual-consistency contract: the diff is a *snapshot judgment* over the folders we synced
    this run. It is NOT atomic across folders — a concurrent server-side move during sync can
    produce stale presence claims that self-correct on the next sync. A message that "looks gone"
    here may be in a folder we don't sync, or in transit. The `.eml` file on disk is preserved
    regardless of the gone flag — if you ever need to recover from a misclaim, the bytes are
    still in `mails/<sha256>.eml` and you can grep through them or re-sync to discover the
    current location.
    """
    if new_count:
        ctx.log(f"  Fetched {new_count} new email(s)", Verbosity.INFO)

    changelog = []
    for content_hash, entry in store.messages.items():
        subj = safe_str(entry.get("subject", "(no subject)")[:50], allow_newlines=False)
        if content_hash not in server_state:
            if is_live(entry):
                changelog.append(("D", content_hash, subj, entry))
        else:
            current_folders = {loc["folder"] for loc in server_state[content_hash]}
            previous_folders = {h["folder"] for h in entry.get("history", []) if not h.get("removed")}
            new_folders = current_folders - previous_folders
            removed_folders = previous_folders - current_folders
            if new_folders or removed_folders:
                prev = (
                    ", ".join(safe_str(f, allow_newlines=False) for f in sorted(removed_folders))
                    if removed_folders
                    else ""
                )
                curr = ", ".join(safe_str(f, allow_newlines=False) for f in sorted(new_folders)) if new_folders else ""
                desc = f"{prev} -> {curr}" if prev and curr else (f"-> {curr}" if curr else f"{prev} -> (removed)")
                changelog.append(("M", content_hash, f"{subj}  ({desc})", entry))

    if not changelog:
        ctx.log(
            f"\nSync complete for {account.name}: {new_count} new, no server-side changes detected.",
            Verbosity.INFO,
        )
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
        ctx.log("  Server-side changes discarded (newly fetched emails are still saved).", Verbosity.INFO)
        store.save()
        return

    for kind, content_hash, _desc, entry in changelog:
        if kind == "D":
            # No current location anywhere we synced — mark every live history entry removed.
            # The .eml file stays on disk; resurrection (if the message reappears) is handled
            # naturally by the fetch loop appending a fresh live entry.
            for h in entry.get("history", []):
                h["removed"] = True
        elif kind == "M":
            current_folders = {loc["folder"] for loc in server_state[content_hash]}
            # Mirror the fix in `_fetch_all_emails`: only consider live history entries when
            # deciding whether a folder is "already in history." Otherwise a folder we previously
            # left and are now back in (entry has removed=True) wouldn't get a fresh live entry.
            for loc in server_state[content_hash]:
                live_folder_names = {h["folder"] for h in entry.get("history", []) if not h.get("removed")}
                if loc["folder"] not in live_folder_names:
                    entry.setdefault("history", []).append(loc)
            for h in entry.get("history", []):
                if h["folder"] not in current_folders:
                    h["removed"] = True

    store.save()
    ctx.log(f"  Applied: {len(deletions)} deletion(s), {len(moves)} move(s).", Verbosity.INFO)


def _summarize_errors(ctx):
    """Render `ctx.errors` for the user — one-line grouped count always (Verbosity.ERROR so it's
    visible at every verbosity level), per-event detail lines at DEBUG. Hint to bump verbosity
    is appended at less-than-DEBUG so the user knows where to look for specifics."""
    if not ctx.errors:
        return
    by_kind = {}
    for e in ctx.errors:
        by_kind.setdefault(e.kind, []).append(e)
    parts = [f"{kind} ({len(events)})" for kind, events in sorted(by_kind.items())]
    summary = f"  {len(ctx.errors)} issue(s) during sync: {', '.join(parts)}"
    if ctx.param.verbosity != Verbosity.DEBUG:
        summary += " — run with verbose=2 for details"
    ctx.log(summary, Verbosity.ERROR)
    for kind in sorted(by_kind):
        for e in by_kind[kind]:
            ctx.log(f"    [{kind}] {e.detail}", Verbosity.DEBUG)


def format_date(raw_date):
    try:
        return parsedate_to_datetime(raw_date).strftime("%Y-%m-%d:%H-%M-%S%z")
    except Exception:
        return safe_str(raw_date or "", allow_newlines=False)


def _date_cell(raw):
    """Render a date for the read UI list column with its color: explicit markers for
    missing/unparseable so problems don't get swept under the rug. Returns (text, color).
      - missing/empty:  ('[EMPTY]', RED)
      - unparseable:    ('[WRONG VALUE]: <raw>', RED)
      - parseable:      ('YYYY-MM-DD:HH-MM-SS+TZ', None — default color)"""
    if not raw:
        return "[EMPTY]", Color.RED
    try:
        return parsedate_to_datetime(raw).strftime("%Y-%m-%d:%H-%M-%S%z"), None
    except Exception:
        return f"[WRONG VALUE]: {safe_str(raw, allow_newlines=False)}", Color.RED


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def internaldate_key(entry):
    """Sort key for read_emails: parse INTERNALDATE, normalize to aware UTC, EPOCH on failure."""
    raw = entry.get("internaldate") or ""
    try:
        dt = parsedate_to_datetime(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return _EPOCH


def build_email_message(sender, recipients, subject, body, attachment_paths=None):
    """Build a MIMEMultipart email message. Pure function — no I/O except reading attachments."""
    message = MIMEMultipart()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
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
    return message


@raise_smexception_on_connection_error
def send_email(account_config, recipients, subject, body, ctx: Context, attachment_paths=None):
    sender_email = account_config.username
    message = build_email_message(sender_email, recipients, subject, body, attachment_paths)

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
        ctx.log("Email sent successfully!", Verbosity.INFO)
    except SMTPAuthenticationError as exc:
        raise SMException(f"Auth error:\n{str(exc)}") from exc
    except Exception as exc:
        raise SMException(f"Error sending email: {str(exc)}") from exc
    finally:
        try:
            server.quit()
        except Exception:
            pass


def kiss_extract_text_from_msg(msg):
    """Naive text extraction from an already-parsed email.message: prefers text/plain,
    falls back to tag-stripped HTML. HTML handling is intentionally dumb (no entity
    decoding bugs aside, no style/script removal) — good enough until it isn't."""
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
        return unescape(html)
    return "(no text content)"


def kiss_extract_text_from_eml(eml_path):
    with Path(eml_path).open("rb") as f:
        return kiss_extract_text_from_msg(message_from_bytes(f.read()))


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _save_attachment_action(attachments):
    """Interactive save flow. Prompts for index (if >1) and destination directory."""
    if len(attachments) == 1:
        idx = 1
    else:
        try:
            raw = input(f"  Save which attachment? [1-{len(attachments)}]: ").strip()
        except EOFError:
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(attachments)):
            print(f"  Invalid number: {raw}")
            return
        idx = int(raw)
    try:
        dest = input("  Save to directory [.]: ").strip() or "."
    except EOFError:
        return
    filename, content = attachments[idx - 1]
    try:
        target = save_attachment_bytes(content, dest, filename)
    except OSError as exc:
        print(f"  Failed to save: {exc}")
        return
    print(f"  Saved: {target}")


def read_emails(account: MailConnectionInfos, ctx: Context):
    snapshot = Store.load_snapshot(account.local_store_path)
    _read_emails_ui(account, snapshot, ctx)


_AUTH_RESULT_RE = re.compile(r"\b(dkim|spf|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


def parse_authentication_results(msg):
    """Extract DKIM/SPF/DMARC verdicts from the message's Authentication-Results header(s).
    Returns a dict like {'dkim': 'pass', 'spf': 'fail'}; empty dict if absent or unparseable.
    Multiple headers are merged (last occurrence wins per method — most-recent receiver in the
    chain). Other auth methods (iprev, arc, smime, ...) are deliberately ignored — out of scope.

    We're surfacing the receiving MTA's verdict, not re-verifying. SPF needs the SMTP-time IP
    we never see; DKIM may legitimately fail after MTA-side rewrites. The provider's verdict in
    the header is what matters for "should I be suspicious of this sender?" UX."""
    results = {}
    for header_value in msg.get_all("Authentication-Results") or []:
        for match in _AUTH_RESULT_RE.finditer(header_value):
            method = match.group(1).lower()
            verdict = match.group(2).lower()
            results[method] = verdict
    return results


def _format_auth_results(auth):
    """Render a parsed auth-results dict as a colorized one-liner. Empty dict → empty string."""
    if not auth:
        return ""
    pieces = []
    for method, verdict in sorted(auth.items()):
        if verdict == "pass":
            color = Color.GREEN.value
        elif verdict in ("fail", "softfail", "permerror", "temperror"):
            color = Color.RED.value
        else:
            color = Color.WHITE.value
        pieces.append(f"{color}{method.upper()}={verdict}{Color.WHITE.value}")
    return " | ".join(pieces)


def _load_message_for_display(content_hash, mails_path, ctx):
    """Load the .eml + parse + list attachments for one message. Recoverable failures (missing
    file, read I/O, parse error, attachment-walk crash) are recorded as `read_failed` ErrorEvents
    and returned as None — the UI loop continues. Returns (msg, attachments) on success."""
    eml_path = mails_path / f"{content_hash}.eml"
    if not eml_path.exists():
        ctx.record_error(
            "read_failed",
            f"missing .eml for {content_hash[:12]}: {eml_path}",
        )
        return None
    try:
        with eml_path.open("rb") as f:
            msg = message_from_bytes(f.read())
        return msg, list_attachments(msg)
    except Exception as exc:
        ctx.record_error(
            "read_failed",
            f"failed to load .eml for {content_hash[:12]}: {type(exc).__name__}: {exc}",
        )
        return None


def _require_tty():
    """Raise SMException if stdin is not a TTY. Carved out so tests can patch the check."""
    if not sys_stdin.isatty():
        raise SMException("sm read requires a TTY")


def _read_key():
    """Read a single keypress in raw mode. Returns a single-char string. Special keys:
    '\\n' or '\\r' = Enter, '\\x1b' = Esc, '\\x7f' = Backspace, '\\x03' = Ctrl-C.
    Restores terminal attrs via try/finally. Tests patch this function directly."""
    fd = sys_stdin.fileno()
    old = tcgetattr(fd)
    try:
        setraw(fd)
        return sys_stdin.read(1)
    finally:
        tcsetattr(fd, TCSADRAIN, old)


def _read_line(prompt):
    """Line-buffered prompt for find queries and save paths. One seam for tests to patch."""
    try:
        return input(prompt)
    except EOFError:
        return ""


def _show_errors_screen(ctx, term_width):
    """Display all `ctx.errors` with full per-event detail, regardless of verbosity.
    User explicitly asked to see them by hitting [e], so verbosity gating doesn't apply."""
    print(f"\n{'═' * term_width}")
    if not ctx.errors:
        print("  No errors recorded.")
    else:
        by_kind = {}
        for e in ctx.errors:
            by_kind.setdefault(e.kind, []).append(e)
        for kind, events in sorted(by_kind.items()):
            label = f"{len(events)} entr{'y' if len(events) == 1 else 'ies'}"
            print(f"  [{kind}] {label}:")
            for e in events:
                print(f"    {safe_str(e.detail, allow_newlines=False)}")
    print(f"{'═' * term_width}")
    print("  Press any key to return", end="", flush=True)
    _read_key()


_CLEAR_SCREEN = "\x1b[H\x1b[2J"  # used only on UI exit, to hand back a clean canvas
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"


def _cell_width(ch):
    """Display width of one char: 0 for empty (wide-char continuation), 2 for East-Asian
    Wide/Fullwidth, 1 otherwise. Caller must pre-sanitize control chars (use safe_str)."""
    if ch == "":
        return 0
    return 2 if east_asian_width(ch) in ("W", "F") else 1


class _Cell:
    __slots__ = ("ch", "color")

    def __init__(self, ch=" ", color=None):
        self.ch = ch
        self.color = color or Color.WHITE


class FB:
    """Cell-grid framebuffer. Per-cell (char, Color). Wide chars take 2 cells; the
    trailing cell holds ch="" as a continuation marker. Inputs must be plain text +
    a Color — never strings with embedded ANSI escapes; the flush owns color emission.
    The flush emits a full-grid paint on each call: no diffing, no leftover state."""

    def __init__(self, w, h):
        self.w = w
        self.h = h
        self.cells = [[_Cell() for _ in range(w)] for _ in range(h)]

    def put(self, row, col, text, color=None):
        """Write `text` at (row, col). Wide chars take 2 cells. Clips to bounds.
        A wide char that won't fit at the right edge is dropped, not half-rendered."""
        if row < 0 or row >= self.h or col >= self.w:
            return
        c = col
        for ch in text:
            if c >= self.w:
                break
            w = _cell_width(ch)
            if w == 0:  # caller passed a continuation marker; ignore
                continue
            if c < 0:
                c += w
                continue
            if w == 2:
                if c + 1 >= self.w:
                    break
                self.cells[row][c] = _Cell(ch, color)
                self.cells[row][c + 1] = _Cell("", color)
                c += 2
            else:
                self.cells[row][c] = _Cell(ch, color)
                c += 1

    def fill_rect(self, row, col, w, h, ch=" ", color=None):
        for r in range(max(0, row), min(self.h, row + h)):
            for cc in range(max(0, col), min(self.w, col + w)):
                self.cells[r][cc] = _Cell(ch, color)

    def dim_rect(self, row, col, w, h):
        """Replace the fg color of every cell in the rect with DIM, preserving chars.
        Used to grey out the base layer before drawing a modal on top."""
        for r in range(max(0, row), min(self.h, row + h)):
            for cc in range(max(0, col), min(self.w, col + w)):
                self.cells[r][cc].color = Color.DIM

    def region(self, row, col, w, h):
        """Sub-FB view: writes translate to parent coords + clip to the box. Use for
        modal contents so the renderer can think in box-local (0,0)..(w,h) coords."""
        return _Region(self, row, col, w, h)

    def serialize(self):
        """Return a single string with cursor positioning + colored chars for the whole
        grid. Caller writes it to stdout in one flush. Trailing reset leaves the terminal
        in a known color so any later writes don't inherit the last cell's color."""
        parts = ["\x1b[H"]
        cur_color = None
        for r in range(self.h):
            parts.append(f"\x1b[{r + 1};1H")
            cc = 0
            while cc < self.w:
                cell = self.cells[r][cc]
                if cell.ch == "":  # wide-char continuation
                    cc += 1
                    continue
                if cell.color is not cur_color:
                    parts.append(cell.color.value)
                    cur_color = cell.color
                parts.append(cell.ch)
                cc += _cell_width(cell.ch)
        if cur_color is not Color.WHITE:
            parts.append(Color.WHITE.value)
        return "".join(parts)


class _Region:
    """Bounded sub-FB. put/fill_rect coords are box-local; the region truncates text
    that would overflow its right edge so the modal can't bleed into the dimmed base."""

    def __init__(self, parent, row, col, w, h):
        self.parent = parent
        self.row0 = row
        self.col0 = col
        self.w = w
        self.h = h

    def put(self, row, col, text, color=None):
        if row < 0 or row >= self.h or col >= self.w:
            return
        if col < 0:
            col = 0
        available = self.w - col
        clipped = []
        used = 0
        for ch in text:
            cw = _cell_width(ch)
            if cw == 0:
                continue
            if used + cw > available:
                break
            clipped.append(ch)
            used += cw
        self.parent.put(self.row0 + row, self.col0 + col, "".join(clipped), color)

    def fill_rect(self, row, col, w, h, ch=" ", color=None):
        r0 = max(0, row)
        c0 = max(0, col)
        r1 = min(self.h, row + h)
        c1 = min(self.w, col + w)
        if r1 <= r0 or c1 <= c0:
            return
        self.parent.fill_rect(self.row0 + r0, self.col0 + c0, c1 - c0, r1 - r0, ch, color)


def _draw_modal_frame(fb, row, col, w, h):
    """Draw a single-line box frame at (row,col) with size (w,h) and clear its interior.
    Box-drawing chars are width-1, so cell math is straightforward."""
    if w < 2 or h < 2:
        return
    fb.put(row, col, "┌" + "─" * (w - 2) + "┐")
    fb.put(row + h - 1, col, "└" + "─" * (w - 2) + "┘")
    for r in range(row + 1, row + h - 1):
        fb.put(r, col, "│")
        fb.put(r, col + w - 1, "│")
    fb.fill_rect(row + 1, col + 1, w - 2, h - 2, ch=" ")


def _render_folder_menu(
    region,
    working_selection,
    working_set,
    filter_off,
    all_folders,
    preset_labels,
    folder_cursor,
    folder_offset,
    page_size,
):
    """Paint the folder menu into `region` (a sub-FB the size of the modal interior).
    Layout (region-local rows): 0 header, 1 presets, 2 separator, 3..h-2 folder list,
    h-1 bottom legend."""
    W, H = region.w, region.h
    count_label = "all" if filter_off else str(len(working_set))
    region.put(0, 0, f"  Folder filter — {count_label}/{len(all_folders)}   active: {working_selection}")
    # Presets line: emit each label as its own put() so the active one can be colored.
    region.put(1, 0, "  Presets:  ")
    col = len("  Presets:  ")
    for label in preset_labels:
        color = Color.PURP if label == working_selection else Color.WHITE
        region.put(1, col, label, color=color)
        col += len(label) + 2
    region.put(2, 0, "─" * W)
    end = min(folder_offset + page_size, len(all_folders))
    for i, name in enumerate(all_folders[folder_offset:end]):
        idx = folder_offset + i
        marker = "▸ " if idx == folder_cursor else "  "
        ticked = filter_off or (name in working_set)
        box = "[X]" if ticked else "[ ]"
        region.put(3 + i, 0, f"{marker}{box} {safe_str(name, allow_newlines=False)}")
    region.put(H - 1, 0, "  i/k:folder  j/l:preset(live)  space:toggle  Enter:apply  Esc:cancel")


def _folder_menu_ui(state, all_entries, account, ctx):
    """Modal folder filter with config presets + persisted custom state.

    Composes over the read UI: each tick we re-render the (committed-state) read UI
    base into the framebuffer, dim the whole grid, draw a modal box with a 6-cell
    margin, then paint the menu into the box's interior. On small terminals (<40w
    or <14h) the modal falls back to full-screen so the box doesn't shrink past
    usability. The base reflects the *committed* filter (state.selection_current);
    only the menu's own ticks/preset-row track the working preview, so j/l doesn't
    flicker the underlying list.

    Preset row layout:
      [none]   <named presets from config…>   [custom]
    - [none] = filter off (show everything live).
    - [custom] = the user's last freely-edited folder set.
    - A named preset is "active" iff working_selection equals its name.

    Storage model: we track *intent* — which preset is selected — not the resolved
    folder set. Editing a folder while on a named preset rolls into [custom] with the
    edited set. Navigating to a named preset does NOT touch custom. Resolution against
    live config happens at read time, so preset edits in config auto-apply next session.

    Keys: i/k move the folder cursor, j/l move the preset cursor AND apply that preset
    immediately (live preview — the folder ticks reflect the new selection right away).
    Space toggles the folder under the i/k cursor (rolling the selection into [custom]).
    Enter commits + persists; Esc cancels. Mutates state.selection_current +
    folders_selected_in_custom + last_resolved on Enter only."""
    presets = account.folder_presets or {}
    all_folders = _all_folders_from_entries(all_entries, presets)
    if not all_folders:
        return

    preset_labels = ["[none]"] + list(presets.keys()) + ["[custom]"]

    # Initialize working state from persisted state. If the saved selection_current
    # references a preset that's since been deleted, recover into "[custom]" if there's
    # anything to recover with (existing custom state preferred over last_resolved
    # snapshot); else fall cleanly to "[none]" rather than landing in an empty-set
    # "[custom]" that would hide everything.
    working_selection = state.selection_current
    working_custom = set(state.folders_selected_in_custom) if state.folders_selected_in_custom is not None else None
    if working_selection not in ("[none]", "[custom]") and working_selection not in presets:
        if working_custom is not None:
            working_selection = "[custom]"
        elif state.last_resolved is not None:
            working_custom = set(state.last_resolved)
            working_selection = "[custom]"
        else:
            working_selection = "[none]"

    def working_resolved():
        """Resolve the working selection to (folder_set, filter_off)."""
        if working_selection == "[none]":
            return None, True
        if working_selection == "[custom]":
            return (set(working_custom) if working_custom is not None else set()), False
        return set(presets[working_selection]), False

    def preset_idx_of(name):
        try:
            return preset_labels.index(name)
        except ValueError:
            return 0

    preset_cursor = preset_idx_of(working_selection)
    folder_cursor = 0
    folder_offset = 0

    while True:
        W, H = _term_size()
        # 6-cell margin around the modal; fall back to full-screen on small terminals.
        if W >= 40 and H >= 14:
            box_row, box_col = 6, 6
            box_w, box_h = W - 12, H - 12
        else:
            box_row, box_col = 0, 0
            box_w, box_h = W, H
        inner_w = max(1, box_w - 2)
        inner_h = max(1, box_h - 2)
        # 4 rows of chrome inside the modal: header, presets, separator, bottom legend.
        page_size = max(1, inner_h - 4)

        folder_cursor = max(0, min(folder_cursor, len(all_folders) - 1))
        if folder_cursor < folder_offset:
            folder_offset = folder_cursor
        elif folder_cursor >= folder_offset + page_size:
            folder_offset = folder_cursor - page_size + 1
        folder_offset = max(0, min(folder_offset, max(0, len(all_folders) - page_size)))

        # Recompute the base read-UI view from *committed* state, so the dimmed
        # background reflects what would be there if the modal closed without commit.
        enabled = _resolve_filter(
            state.selection_current,
            state.folders_selected_in_custom,
            state.last_resolved,
            presets,
        )
        base_entries = _entries_visible(all_entries, state, enabled)
        base_state_page = max(1, H - 5)
        if base_entries:
            base_start = max(0, min(state.offset, max(0, len(base_entries) - base_state_page)))
        else:
            base_start = 0
        base_end = min(base_start + base_state_page, len(base_entries))

        fb = FB(W, H)
        # Stash & restore page_size so the base render uses the right viewport size
        # without the modal mutating live state.
        saved_page_size = state.page_size
        state.page_size = base_state_page
        try:
            _render_read_ui(fb, account, ctx, state, base_entries, base_start, base_end)
        finally:
            state.page_size = saved_page_size
        fb.dim_rect(0, 0, W, H)
        _draw_modal_frame(fb, box_row, box_col, box_w, box_h)
        region = fb.region(box_row + 1, box_col + 1, inner_w, inner_h)
        working_set, filter_off = working_resolved()
        _render_folder_menu(
            region,
            working_selection,
            working_set,
            filter_off,
            all_folders,
            preset_labels,
            folder_cursor,
            folder_offset,
            page_size,
        )
        print(fb.serialize(), end="", flush=True)

        key = _read_key()
        if key in ("\n", "\r"):
            state.selection_current = working_selection
            state.folders_selected_in_custom = set(working_custom) if working_custom is not None else None
            state.last_resolved = _resolve_filter(working_selection, working_custom, None, presets)
            _save_folder_state(
                account.local_store_path,
                state.selection_current,
                state.folders_selected_in_custom,
                state.last_resolved,
            )
            return
        if key in ("\x1b", "\x03", "q"):
            return
        if key == "i":
            folder_cursor -= 1
        elif key == "k":
            folder_cursor += 1
        elif key == "I":
            folder_cursor -= 10
        elif key == "K":
            folder_cursor += 10
        elif key in ("j", "l"):
            if key == "j":
                preset_cursor = max(0, preset_cursor - 1)
            else:
                preset_cursor = min(len(preset_labels) - 1, preset_cursor + 1)
            # Live-apply: moving the preset cursor immediately applies that preset, so
            # the folder ticks update as a preview. No separate "Space to apply" step.
            target = preset_labels[preset_cursor]
            if target == "[custom]" and working_custom is None:
                # First-time landing on [custom] with no prior custom: seed it from the
                # current visible set so the preview isn't an empty-checkboxes surprise.
                cur_set, off = working_resolved()
                working_custom = set(all_folders) if off else set(cur_set)
            working_selection = target
        elif key == " ":
            # Toggle the folder under the i/k cursor. Rolls the selection into [custom]
            # and moves the preset cursor to track it, so the color indicator stays in
            # sync and a subsequent j/l move starts from the right place.
            cur_set, off = working_resolved()
            effective = set(all_folders) if off else set(cur_set)
            name = all_folders[folder_cursor]
            if name in effective:
                effective.discard(name)
            else:
                effective.add(name)
            working_custom = effective
            working_selection = "[custom]"
            preset_cursor = preset_idx_of("[custom]")


def _read_emails_ui(account, snapshot, ctx):
    if not snapshot.messages:
        raise SMException(f"No emails found for account {account.name}. Run sync first.")

    all_entries = [(h, e) for h, e in snapshot.messages.items() if is_live(e)]
    all_entries.sort(key=lambda x: internaldate_key(x[1]), reverse=True)
    if not all_entries:
        raise SMException(f"No non-deleted emails found for account {account.name}.")

    _require_tty()
    state = ReadUIState()
    state.selection_current, state.folders_selected_in_custom, state.last_resolved = _load_folder_state(
        account.local_store_path
    )

    print(_HIDE_CURSOR, end="")
    try:
        _run_read_loop(account, snapshot, ctx, state, all_entries)
    finally:
        # Restore cursor + clear screen so the shell prompt comes back on a clean canvas.
        print(_SHOW_CURSOR + _CLEAR_SCREEN, end="")


def _term_size():
    try:
        sz = os.get_terminal_size()
        return sz.columns, sz.lines
    except (ValueError, OSError):
        return 80, 24


def _render_read_ui(fb, account, ctx, state, entries, start, end):
    """Paint the read UI into `fb`. Pure render: no I/O, no state mutation. Layout:
    rows 0/2/H-2 are rules, row 1 the header, row H-1 the bottom action line, rows
    3..H-3 the list (page_size = H - 5)."""
    W, H = fb.w, fb.h
    rule = "─" * W
    fb.put(0, 0, rule)
    if entries:
        header = (
            f"  {account.name} — entry {state.cursor + 1}/{len(entries)} "
            f"(showing {start + 1}–{end} of {len(entries)})"
        )
    else:
        header = f"  {account.name} — 0 entries"
    if state.find_query and not state.find_mode:
        header += f"   find: {state.find_query}"
    if state.selection_current != "[none]":
        header += f"   filter: {state.selection_current}"
    fb.put(1, 0, header)
    fb.put(2, 0, rule)
    list_rows = max(0, H - 5)
    date_field = "date" if state.header_date else "internaldate"
    DATE_W = 24
    if entries:
        for i, (_content_hash, entry) in enumerate(entries[start:end]):
            num = start + i + 1
            frm = safe_str(entry.get("from", "")[:30], allow_newlines=False)
            subj = safe_str(entry.get("subject", "(no subject)"), allow_newlines=False)
            marker = "▸ " if (start + i) == state.cursor else "  "
            date_text, date_color = _date_cell(entry.get(date_field, ""))
            if len(date_text) > DATE_W:
                date_text = date_text[: DATE_W - 1] + "…"
            # Three puts per row so the date cell can carry its own color (red for
            # missing/unparseable). Fixed column boundaries: prefix=0..40, date=40..64,
            # subj=66..W-1; the gap cells stay as the FB's default-init spaces.
            prefix_left = f"{marker}{num:>4}  {frm:<30}  "
            fb.put(3 + i, 0, prefix_left)
            fb.put(3 + i, len(prefix_left), f"{date_text:<{DATE_W}}", color=date_color)
            subj_col = len(prefix_left) + DATE_W + 2
            max_subj = W - subj_col - 1
            if max_subj > 0 and len(subj) > max_subj:
                subj = subj[: max_subj - 1] + "…"
            fb.put(3 + i, subj_col, subj)
    else:
        hint = (
            "no email with the current filters"
            if (state.find_query or state.selection_current != "[none]")
            else "no email"
        )
        mid = list_rows // 2
        pad = max(0, (W - len(hint)) // 2)
        fb.put(3 + mid, pad, hint)
    fb.put(H - 2, 0, rule)
    if state.find_mode:
        bottom = f"  find: {state.find_query}_   (Enter:apply  Esc:cancel  Backspace:delete)"
    else:
        date_tag = "hdr" if state.header_date else "srv"
        bottom = (
            f"  i/k:line  I/K:±10  j/l:edge  J/L:top/bot  Enter:open  #:jump  f:find  m:folders  d:date({date_tag})"
        )
        if ctx.errors:
            bottom += f"  e:errors({len(ctx.errors)})"
        bottom += "  q:quit"
        if state.digit_buffer:
            bottom += f"   buffer: {state.digit_buffer}"
    fb.put(H - 1, 0, bottom)


def _run_read_loop(account, snapshot, ctx, state, all_entries):
    while True:
        term_width, term_height = _term_size()
        # 5 lines of chrome: top rule, header, top rule, bottom rule, actions.
        # Updated each redraw so terminal resizes apply without restart, and so j/l
        # page nav (below) uses the current page_size.
        state.page_size = max(1, term_height - 5)

        enabled_folders = _resolve_filter(
            state.selection_current,
            state.folders_selected_in_custom,
            state.last_resolved,
            account.folder_presets,
        )
        entries = _entries_visible(all_entries, state, enabled_folders)

        # Cursor/offset clamping. Empty list is a normal render with a hint, not a special
        # screen — keeps the user's context (header, chrome, bottom row) intact.
        if entries:
            state.cursor = max(0, min(state.cursor, len(entries) - 1))
            if state.cursor < state.offset:
                state.offset = state.cursor
            elif state.cursor >= state.offset + state.page_size:
                state.offset = state.cursor - state.page_size + 1
            state.offset = max(0, min(state.offset, max(0, len(entries) - state.page_size)))
        else:
            state.cursor = 0
            state.offset = 0
        start = state.offset
        end = min(start + state.page_size, len(entries))

        fb = FB(term_width, term_height)
        _render_read_ui(fb, account, ctx, state, entries, start, end)
        print(fb.serialize(), end="", flush=True)

        key = _read_key()

        # While editing the find query, keystrokes feed the editor instead of the nav
        # dispatch. The list above re-filters every frame as find_query changes —
        # substring match is cheap enough for live updates even on large mailboxes.
        if state.find_mode:
            if key in ("\n", "\r"):
                state.find_mode = False
                state.cursor = 0
                state.offset = 0
            elif key in ("\x1b", "\x03"):
                state.find_mode = False
                state.find_query = ""
                state.cursor = 0
                state.offset = 0
            elif key in ("\x7f", "\x08"):  # DEL or BS — terminal varies
                state.find_query = state.find_query[:-1]
            elif key and key.isprintable():
                state.find_query += key
            # else: ignore unhandled control chars (arrow keys, tab, etc.)
            continue

        # If the list is empty (find/folder filter matched nothing), navigation keys are
        # meaningless. Only quit and filter-editing stay live so the user can recover.
        if not entries:
            if key in ("q", "\x03"):
                return
            if key == "f":
                state.find_mode = True
            elif key == "m":
                _folder_menu_ui(state, all_entries, account, ctx)
                state.cursor = 0
                state.offset = 0
            elif key == "d":
                state.header_date = not state.header_date
            continue

        if key in ("q", "\x03"):
            return
        elif key == "i":
            state.cursor -= 1
            state.digit_buffer = ""
        elif key == "k":
            state.cursor += 1
            state.digit_buffer = ""
        elif key == "I":
            state.cursor -= 10
            state.digit_buffer = ""
        elif key == "K":
            state.cursor += 10
            state.digit_buffer = ""
        elif key == "j":
            # First press: snap to top of current viewport. Second press at top: page up
            # by a full viewport (cursor and offset move together). Lets one key serve both
            # fine-grained "get to the top of what I can see" and bulk pagination.
            if state.cursor > state.offset:
                state.cursor = state.offset
            else:
                new_offset = max(0, state.offset - state.page_size)
                state.cursor = new_offset
                state.offset = new_offset
            state.digit_buffer = ""
        elif key == "l":
            # Mirror of j: first press snaps cursor to bottom of viewport; second press at
            # the bottom pages down. Offset follows cursor in the redraw clamp.
            screen_bottom = min(state.offset + state.page_size - 1, len(entries) - 1)
            if state.cursor < screen_bottom:
                state.cursor = screen_bottom
            else:
                state.cursor = min(state.cursor + state.page_size, len(entries) - 1)
            state.digit_buffer = ""
        elif key == "J":
            state.cursor = 0
            state.digit_buffer = ""
        elif key == "L":
            state.cursor = len(entries) - 1
            state.digit_buffer = ""
        elif key.isdigit():
            state.digit_buffer += key
        elif key == "\x1b":
            # Layered Esc: clear a pending digit buffer first, otherwise clear an active find.
            # Folder filter (pass 5) is not cleared on Esc — that's a deliberate setup, not a
            # quick toggle.
            if state.digit_buffer:
                state.digit_buffer = ""
            elif state.find_query:
                state.find_query = ""
                state.cursor = 0
                state.offset = 0
        elif key == "f":
            state.find_mode = True
            state.digit_buffer = ""
        elif key == "m":
            _folder_menu_ui(state, all_entries, account, ctx)
            state.cursor = 0
            state.offset = 0
            state.digit_buffer = ""
        elif key == "d":
            state.header_date = not state.header_date
            state.digit_buffer = ""
        elif key in ("\n", "\r"):
            if state.digit_buffer:
                idx = int(state.digit_buffer) - 1
                state.digit_buffer = ""
                if not (0 <= idx < len(entries)):
                    continue
                state.cursor = idx
            content_hash, entry = entries[state.cursor]
            if _view_email_ui(content_hash, entry, snapshot, ctx, term_width) == "quit":
                return
        elif key == "e" and ctx.errors:
            _show_errors_screen(ctx, term_width)


def _view_email_ui(content_hash, entry, snapshot, ctx, term_width):
    """Display one email body. Returns 'back' or 'quit' to the caller."""
    loaded = _load_message_for_display(content_hash, snapshot.mails_path, ctx)
    if loaded is None:
        print(_CLEAR_SCREEN, end="")
        print("  Failed to load email — recorded; press [e] to view details.")
        print("  Press any key to return.", end="", flush=True)
        key = _read_key()
        return "quit" if key in ("q", "\x03") else "back"
    msg, attachments = loaded

    while True:
        print(_CLEAR_SCREEN, end="")
        print(f"{'═' * term_width}")
        print(f"  From:    {safe_str(entry.get('from', ''), allow_newlines=False)}")
        print(f"  Date:    {format_date(entry.get('date', ''))}")
        print(f"  Subject: {safe_str(entry.get('subject', ''), allow_newlines=False)}")
        auth_line = _format_auth_results(parse_authentication_results(msg))
        if auth_line:
            print(f"  Auth:    {auth_line}")
        print(f"{'═' * term_width}")
        print(safe_str(kiss_extract_text_from_msg(msg), allow_newlines=True))
        print(f"{'═' * term_width}")
        if attachments:
            print("  Attachments:")
            for n, (name, content) in enumerate(attachments, 1):
                print(f"    {n}. {safe_str(name, allow_newlines=False)} ({_human_size(len(content))})")
            print(f"{'═' * term_width}")
        actions = "  b back  q quit"
        if attachments:
            actions += "  s save attachment"
        print(actions, end="", flush=True)

        key = _read_key()
        if key in ("q", "\x03"):
            return "quit"
        if key in ("b", "\x1b"):
            return "back"
        if key == "s" and attachments:
            _save_attachment_action(attachments)


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
        '    "folder_presets": {"business": ["Work", "Projects"], "personal": ["INBOX"]}  (optional, for read UI)',
        "───────────────────────",
        "- sm send recipient=a@b.com [recipient=c@d.com ...] subject=title body=something [account=name] [file=path]",
        "- sm sync [account=name] [yes] [verbose=0|1|2]      ──➤ fetch new + review deletions/moves",
        "- sm read [account=name]                             ──➤ read emails in terminal",
        "- sm resync-internaldate [account=name]              ──➤ backfill missing INTERNALDATE (no body fetch)",
        "───────────────────────",
        "  verbose= accepts 0/1/2 or error/info/debug (applies to all commands)",
        "You need to generate an app specific password for gmail or other mail clients",
    ]
    red_indexes = (list(range(2, 18)) if wrong_config else []) + ([19] if wrong_command else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args(argv):
    if len(argv) < 2 or argv[1] not in ["send", "sync", "read", "resync-internaldate"]:
        return None, Context()
    remaining = [v for v in argv[2:] if not v.startswith("verbose=")]
    verbose_args = [v for v in argv[2:] if v.startswith("verbose=")]
    ctx = Context()
    if verbose_args:
        val = verbose_args[-1].split("=", 1)[1].lower()
        mapping = {"0": "ERROR", "1": "INFO", "2": "DEBUG", "error": "ERROR", "info": "INFO", "debug": "DEBUG"}
        if val not in mapping:
            raise SMException(f"Invalid verbose level: {val} (use 0/1/2 or error/info/debug)")
        ctx.param.verbosity = Verbosity[mapping[val]]
    if argv[1] == "sync":
        account = next((v[v.index("=") + 1 :] for v in remaining if v.startswith("account=")), None)
        auto_apply = "yes" in remaining
        invalid = [v for v in remaining if not v.startswith("account=") and v != "yes"]
        if invalid:
            raise SMException(f"Invalid options for sync: {'  ;  '.join(invalid)}")
        return {"action": "sync", "account": account, "auto_apply": auto_apply}, ctx
    if argv[1] == "read":
        account = next((v[v.index("=") + 1 :] for v in remaining if v.startswith("account=")), None)
        invalid = [v for v in remaining if not v.startswith("account=")]
        if invalid:
            raise SMException(f"Invalid options for read: {'  ;  '.join(invalid)}")
        return {"action": "read", "account": account}, ctx
    if argv[1] == "resync-internaldate":
        account = next((v[v.index("=") + 1 :] for v in remaining if v.startswith("account=")), None)
        invalid = [v for v in remaining if not v.startswith("account=")]
        if invalid:
            raise SMException(f"Invalid options for resync-internaldate: {'  ;  '.join(invalid)}")
        return {"action": "resync-internaldate", "account": account}, ctx
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
    return {**opts, "action": "send"}, ctx


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
    args, ctx = consume_args(argv)
    if not args:
        return usage()
    if args["action"] == "send":
        account_name = args["account"] or config.get("default_account_for_send")
        if not account_name:
            raise SMException("No account specified and no default_account_for_send in config")
        send_email(
            resolve_accounts(mail_connections_infos, account_name)[0],
            args["recipients"],
            args["subject"],
            args["body"],
            ctx,
            args["files"],
        )
    elif args["action"] == "sync":
        try:
            for account in resolve_accounts(mail_connections_infos, args["account"]):
                sync_emails(account, ctx, auto_apply=args["auto_apply"])
        finally:
            _summarize_errors(ctx)  # cumulative across all accounts; fires on success and exception alike
    elif args["action"] == "resync-internaldate":
        try:
            for account in resolve_accounts(mail_connections_infos, args["account"]):
                resync_internaldate(account, ctx)
        finally:
            _summarize_errors(ctx)
    elif args["action"] == "read":
        accounts = resolve_accounts(mail_connections_infos, args["account"])
        if len(accounts) == 1:
            read_emails(accounts[0], ctx)
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
