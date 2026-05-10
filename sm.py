#!/usr/bin/env python

"""
sm - Simple Mail client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
"""

import base64
import os
import re
from collections import namedtuple
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from email import encoders, message_from_bytes
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
from urllib.error import HTTPError

CONFIG_PATH = Path.home() / ".config" / "sm" / "config.json"
LOCK_PATH = Path.home() / ".config" / "sm" / ".lock"

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])

Verbosity = Enum("Verbosity", [("ERROR", 0), ("INFO", 1), ("DEBUG", 2)])


@dataclass
class Param:
    verbosity: Verbosity = Verbosity.ERROR


@dataclass
class ErrorEvent:
    kind: str       # "parse_list", "select_failed", "select_error", ...
    detail: str     # human-readable, sanitized
    raw: bytes = None  # the original bytes/repr if useful for debug


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
        self.messages = None       # {sha256_hash: entry}
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
    """Write content to dest_dir/<sanitized_name>. mkdir -p dest_dir. Rename on collision (_1, _2, ...). Returns Path."""
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
        if b[i:i + 1] != b"&":
            out.append(b[i:i + 1].decode("ascii", "replace"))
            i += 1
            continue
        end = b.find(b"-", i + 1)
        if end == -1:
            out.append(b[i:].decode("ascii", "replace"))
            break
        payload = b[i + 1:end]
        if not payload:
            out.append("&")
        else:
            std = payload.replace(b",", b"/")
            std += b"=" * ((4 - len(std) % 4) % 4)
            try:
                out.append(base64.b64decode(std, validate=True).decode("utf-16-be"))
            except Exception:
                out.append(b[i:end + 1].decode("ascii", "replace"))
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
    if i >= n or raw[i:i + 1] != b"(":
        return _fail("no opening paren on flag list")
    i += 1
    flags_start = i
    depth = 1
    while i < n and depth > 0:
        c = raw[i:i + 1]
        if c == b"(":
            depth += 1
        elif c == b")":
            depth -= 1
        i += 1
    if depth != 0:
        return _fail("unterminated flag list")
    flags_bytes = raw[flags_start:i - 1]

    while i < n and raw[i:i + 1] in (b" ", b"\t"):
        i += 1

    # 2) delim: NIL or "<char>" with optional backslash escape
    if raw[i:i + 3] == b"NIL":
        delim = None
        i += 3
    elif raw[i:i + 1] == b'"':
        i += 1
        if i >= n:
            return _fail("truncated after opening quote on delimiter")
        if raw[i:i + 1] == b"\\":
            i += 1
            if i >= n:
                return _fail("truncated after backslash escape in delimiter")
        delim = raw[i:i + 1].decode("ascii", "replace")
        i += 1
        if i >= n or raw[i:i + 1] != b'"':
            return _fail("missing closing quote on delimiter")
        i += 1
    else:
        return _fail("expected delimiter (NIL or quoted char)")

    while i < n and raw[i:i + 1] in (b" ", b"\t"):
        i += 1
    if i >= n:
        return _fail("missing mailbox name")

    # 3) mailbox-name: quoted, literal, or atom
    if raw[i:i + 1] == b'"':
        i += 1
        chars = bytearray()
        while i < n and raw[i:i + 1] != b'"':
            if raw[i:i + 1] == b"\\" and i + 1 < n:
                chars.append(raw[i + 1])
                i += 2
            else:
                chars.append(raw[i])
                i += 1
        if i >= n:
            return _fail("unterminated quoted mailbox name")
        name_bytes = bytes(chars)
    elif raw[i:i + 1] == b"{":
        end = raw.find(b"}", i)
        if end == -1:
            return _fail("malformed literal length marker (no closing brace)")
        try:
            count = int(raw[i + 1:end])
        except ValueError:
            return _fail("non-numeric literal length")
        j = end + 1
        if raw[j:j + 2] == b"\r\n":
            j += 2
        elif raw[j:j + 1] in (b"\r", b"\n"):
            j += 1
        if j + count > n:
            return _fail("literal length exceeds available bytes")
        name_bytes = raw[j:j + count]
    else:
        start = i
        while i < n and raw[i:i + 1] not in (b" ", b"\t", b"\r", b"\n"):
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
            if not _is_safe_folder_name(folder):
                ctx.log(f"Skipping unsafe folder name: {safe_str(folder, allow_newlines=False)}", Verbosity.DEBUG)
                ctx.record_error("unsafe_folder_name", f"folder {folder!r} contains disallowed bytes; refusing to SELECT")
                continue
            try:
                status, messages = mail.select(f'"{folder}"')
                if status != "OK":
                    ctx.log(f"Skipping folder (select failed): {safe_str(folder, allow_newlines=False)}", Verbosity.DEBUG)
                    ctx.record_error("select_failed", f"SELECT returned {status} for folder {folder!r}")
                    continue
            except Exception as exc:
                ctx.log(f"Skipping folder: {safe_str(folder, allow_newlines=False)}", Verbosity.DEBUG)
                ctx.record_error("select_error", f"SELECT raised {type(exc).__name__} for folder {folder!r}: {exc}")
                continue

            # UIDVALIDITY check: if the server's value differs from what we stored, our cached
            # (folder, uid) mappings are stale — drop them so this folder gets fully re-fetched.
            # Content-hash dedup avoids rewriting .eml files we already have on disk.
            current_uidv = _read_uidvalidity(mail)
            stored_uidv = store.folder_states.get(folder, {}).get("uidvalidity")
            if current_uidv is not None and stored_uidv is not None and current_uidv != stored_uidv:
                removed = _invalidate_cache_for_folder(known_uids, folder)
                ctx.log(
                    f"UIDVALIDITY changed for {safe_str(folder, allow_newlines=False)}: "
                    f"{stored_uidv} -> {current_uidv}; re-fetching {removed} cached entr{'y' if removed == 1 else 'ies'}",
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
                            store.save()
                        else:
                            # Folder is currently live. UID may have changed (UIDVALIDITY bump on
                            # a message that stayed in the folder); update it in place.
                            h = live[folder]
                            if h.get("uid") != uid:
                                h["uid"] = uid
                                store.save()
                    else:
                        email_data = message_from_bytes(raw_email)
                        store.messages[content_hash] = {
                            "message_id": email_data.get("Message-ID", ""),
                            "subject": email_data.get("Subject", ""),
                            "from": email_data.get("From", ""),
                            "date": email_data.get("Date", ""),
                            "internaldate": internaldate,
                            "history": [{"folder": folder, "uid": uid}],
                        }
                        store.save()
                        new_count += 1
                        ctx.log(f"Fetched: {safe_str(email_data.get('Subject', '(no subject)')[:50], allow_newlines=False)}", Verbosity.DEBUG)
                print(f"\r    {i}/{len(uids)}", end="", flush=True)
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
            choice = input(
                f"  sync failed after {max_silent_retries + 1} attempt(s): {last_exc}\n"
                f"  Retry? [y/N] "
            ).strip().lower()
        except EOFError:
            choice = "n"
        if choice not in ("y", "yes"):
            raise last_exc


def is_live(entry):
    """True iff at least one history entry is still live (not marked removed).
    Empty history is treated as gone (defensive — entries are always created with one history item)."""
    return any(not h.get("removed") for h in entry.get("history", []))


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
                prev = ", ".join(safe_str(f, allow_newlines=False) for f in sorted(removed_folders)) if removed_folders else ""
                curr = ", ".join(safe_str(f, allow_newlines=False) for f in sorted(new_folders)) if new_folders else ""
                desc = f"{prev} -> {curr}" if prev and curr else (f"-> {curr}" if curr else f"{prev} -> (removed)")
                changelog.append(("M", content_hash, f"{subj}  ({desc})", entry))

    if not changelog:
        ctx.log(f"\nSync complete for {account.name}: {new_count} new, no server-side changes detected.", Verbosity.INFO)
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
    """Naive text extraction from an already-parsed email.message: prefers text/plain, falls back to tag-stripped HTML.
    HTML handling is intentionally dumb (no entity decoding bugs aside, no style/script removal) — good enough until it isn't."""
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
    print("  Press Enter to return")
    try:
        input()
    except EOFError:
        pass


def _read_emails_ui(account, snapshot, ctx):
    if not snapshot.messages:
        raise SMException(f"No emails found for account {account.name}. Run sync first.")

    entries = [(h, e) for h, e in snapshot.messages.items() if is_live(e)]
    entries.sort(key=lambda x: internaldate_key(x[1]), reverse=True)
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
        actions = "  [number] read  |  [n]ext  [p]rev"
        if ctx.errors:
            actions += f"  |  [e]rrors ({len(ctx.errors)})"
        actions += "  |  [q]uit"
        print(actions)

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
        elif cmd == "e" and ctx.errors:
            _show_errors_screen(ctx, term_width)
        elif cmd.isdigit():
            idx = int(cmd) - 1
            if 0 <= idx < len(entries):
                content_hash, entry = entries[idx]
                loaded = _load_message_for_display(content_hash, snapshot.mails_path, ctx)
                if loaded is None:
                    print("  Failed to load email — recorded; press [e] to view details.")
                    continue
                msg, attachments = loaded

                print(f"\n{'═' * term_width}")
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
                actions = "  [b]ack to list" + ("  [s]ave attachment" if attachments else "") + "  [q]uit"
                print(actions)

                try:
                    cmd2 = input("\n> ").strip().lower()
                except EOFError:
                    break
                if cmd2 == "q":
                    break
                if cmd2 == "s" and attachments:
                    _save_attachment_action(attachments)
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


def consume_args(argv):
    if len(argv) < 2 or argv[1] not in ["send", "sync", "read"]:
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
            args["recipients"], args["subject"], args["body"], ctx, args["files"],
        )
    elif args["action"] == "sync":
        try:
            for account in resolve_accounts(mail_connections_infos, args["account"]):
                sync_emails(account, ctx, auto_apply=args["auto_apply"])
        finally:
            _summarize_errors(ctx)  # cumulative across all accounts; fires on success and exception alike
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
