#!/usr/bin/env python

"""
sm - Simple Mail client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
TODOs and possible improvements: Fill this
"""

import os
from dataclasses import dataclass, fields
from email import encoders, message_from_bytes
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from hashlib import sha256
from imaplib import IMAP4_SSL
from itertools import chain
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
        except HTTPError as exc:
            raise SMException(f"HTTP Error when reaching server: {exc.code}") from exc
        except socket_timeout as exc:
            raise SMException("Timed out") from exc
        except Exception as exc:
            if isinstance(exc, SMException):
                raise exc
            if isinstance(getattr(exc, "reason", None), socket_timeout):
                raise SMException("TLS timed out") from exc  # Most probable cause, should check this is always the case
            if isinstance(getattr(exc, "reason", None), gaierror):
                raise SMException("Failed domain name resolution") from exc
            if isinstance(getattr(exc, "reason", None), SSLCertVerificationError):
                raise SMException("Failed SSL cert validation") from exc
            if isinstance(exc, SSLCertVerificationError):
                raise SMException("Failed SSL cert validation") from exc
            # Keeping this as-is for now, should not happen if everything is handled correctly, add any necessary ones
            raise SMException("Unknown error when trying to reach server") from exc

    return wrapper


def acquire_lock():
    try:
        with LOCK_PATH.open("x"):
            pass
    except FileExistsError:
        raise SMException(
            f"Failed to acquire lock.\nIf no instance of the tool is running, you may remove: {LOCK_PATH}"
        ) from None


def release_lock():
    LOCK_PATH.unlink()


def locked(func):
    def wrapper(*args, **kwargs):
        acquire_lock()
        try:
            return func(*args, **kwargs)
        finally:
            release_lock()

    return wrapper


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


@locked
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


def search_uid_string(uid_max, criteria):
    c = [(t0, f'"{t1}"') for t0, t1 in criteria.items()] + [("UID", f"{uid_max + 1}:*")]
    return f"({' '.join(chain(*c))})"


@raise_smexception_on_connection_error
def quick_and_dirty_backup(config):
    # TODO Better login/logout, gracefully fail for any error
    criteria = {}
    uid_max = 0
    connection_infos = MailConnectionInfos.from_dict(config["accounts"][1])  # TODO Parameterize 1, reuse parameter
    if connection_infos.ssl_cafile is None:  # Dirty quickfix for global ssl_cafile
        connection_infos.ssl_cafile = config.get("ssl_cafile")
    ssl_context = make_pinned_ssl_context(
        connection_infos.pinned_imap_certificate_sha256, cafile=connection_infos.ssl_cafile
    )
    mail = IMAP4_SSL(connection_infos.imap_ssl_host, connection_infos.imap_ssl_port, ssl_context=ssl_context)
    mail.login(connection_infos.username, connection_infos.password)
    status, messages = mail.select("inbox")  # TODO Operate on all folders
    result, data = mail.uid("SEARCH", None, search_uid_string(uid_max, criteria))
    uids = [int(s) for s in data[0].split()]
    print(uids)  # TODO Aggregate and log
    if uids:
        uid_max = max(uids)

    for _xii, uid in enumerate(uids):
        # TODO Here in case the server isn't following UID norms
        if uid > uid_max or True:  # TODO Make a more comprehensive check before working with uids better?
            # TODO If we can ensure we can work with uid, don't get those that we already backed up
            # TODO Handle the deletion of an email by keeping it here but marking it as deleted
            # TODO Handle the move of an email, check first no confusion with deletion
            # TODO - if deletion detected, mark for check, once all inboxes obtained again, mark moved or deleted?
            print(f"\n\n{uid}\n\n")  # TODO Aggregate and log
            result, data = mail.uid("fetch", str(uid), "(RFC822)")
            for response_part in data:
                if isinstance(response_part, tuple):
                    # TODO work on message_from_bytes or message_from_strings
                    # TODO save the message as binary and index in an easily consumable way
                    # response_part[0] is email_identifier
                    email_data = message_from_bytes(response_part[1])
                    save_attachment(Path(config["accounts"][1]["local_store_path"]), email_data)  # TODO Parameterize 1
                    print(response_part[1], email_data.get_payload())  # TODO Better than naive print
                    # TODO Handle save_at in response_part[1] to compute file name instead?
            uid_max = uid
    mail.logout()


def load_index(store_path: Path):
    index_path = store_path / "index.json"
    if index_path.exists():
        with index_path.open() as f:
            return loads(f.read())
    return {}


def save_index(store_path: Path, index: dict):
    index_path = store_path / "index.json"
    with index_path.open("w") as f:
        f.write(dumps(index, indent=2))


@raise_smexception_on_connection_error
def fetch_emails(account: MailConnectionInfos):
    store_path = Path(account.local_store_path)
    mails_path = store_path / "mails"
    mails_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    index = load_index(store_path)

    ssl_context = make_pinned_ssl_context(account.pinned_imap_certificate_sha256, cafile=account.ssl_cafile)
    mail = IMAP4_SSL(account.imap_ssl_host, account.imap_ssl_port, ssl_context=ssl_context)
    mail.login(account.username, account.password)

    try:
        # List all folders
        status, folder_data = mail.list()
        folders = []
        for item in folder_data:
            # Parse folder name from response like: b'(\\HasNoChildren) "/" "INBOX"'
            if isinstance(item, bytes):
                parts = item.decode().rsplit('" "', 1)
                if len(parts) == 2:
                    folders.append(parts[1].rstrip('"'))
        if not folders:
            raise SMException(f"No folders found. Raw response: {folder_data[:3]}...")

        new_count = 0
        for folder in folders:
            try:
                status, messages = mail.select(f'"{folder}"')
                if status != "OK":
                    print(f"Skipping folder (select failed): {folder}")
                    continue
            except Exception:
                print(f"Skipping folder: {folder}")
                continue

            result, data = mail.uid("SEARCH", None, "ALL")
            if not data[0]:
                continue
            uids = [int(s) for s in data[0].split()]

            for uid in uids:
                result, data = mail.uid("fetch", str(uid), "(RFC822 INTERNALDATE)")
                for response_part in data:
                    if not isinstance(response_part, tuple):
                        continue
                    raw_email = response_part[1]
                    content_hash = sha256(raw_email).hexdigest()

                    # Parse INTERNALDATE from response
                    header = response_part[0].decode() if isinstance(response_part[0], bytes) else ""
                    internaldate = ""
                    if "INTERNALDATE" in header:
                        start = header.find('INTERNALDATE "') + 14
                        end = header.find('"', start)
                        internaldate = header[start:end]

                    if content_hash in index:
                        # Update history if new folder
                        existing = index[content_hash]
                        folder_names = [h["folder"] for h in existing.get("history", [])]
                        if folder not in folder_names:
                            existing.setdefault("history", []).append({"folder": folder, "uid": uid})
                            save_index(store_path, index)
                    else:
                        # New email (or orphan recovery)
                        email_data = message_from_bytes(raw_email)
                        eml_path = mails_path / f"{content_hash}.eml"

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
                            temp_path = mails_path / f".{content_hash}.eml.tmp"
                            with temp_path.open("wb") as f:
                                f.write(raw_email)
                            temp_path.rename(eml_path)

                        index[content_hash] = {
                            "message_id": email_data.get("Message-ID", ""),
                            "subject": email_data.get("Subject", ""),
                            "from": email_data.get("From", ""),
                            "date": email_data.get("Date", ""),
                            "internaldate": internaldate,
                            "history": [{"folder": folder, "uid": uid}],
                        }
                        save_index(store_path, index)
                        new_count += 1
                        print(f"Fetched: {email_data.get('Subject', '(no subject)')[:50]}")

        print(f"\nFetched {new_count} new emails for {account.name}")
    finally:
        mail.logout()


@raise_smexception_on_connection_error
def send_email(account_config, recipient_email, subject, body, attachment_paths=None):
    sender_email = account_config.username
    message = MIMEMultipart()
    for k, v in {"From": sender_email, "To": recipient_email, "Subject": subject}.items():
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
        server.sendmail(sender_email, recipient_email, text)
        print("Email sent successfully!")
    except SMTPAuthenticationError as exc:
        raise SMException(f"Auth error:\n{str(exc)}") from exc
    except Exception as exc:
        raise SMException(f"Error sending email: {str(exc)}") from exc
    finally:
        try:
            server.quit()
        except Exception:
            pass


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
        "- sm send recipient=x@y.com subject=title body=something [account=name] [file=path] ──➤ send",
        "- sm fetch [account=name]                                                           ──➤ fetch",
        "- sm backup                                                                         ──➤ backup",
        "───────────────────────",
        "You need to generate an app specific password for gmail or other mail clients",
    ]
    red_indexes = (list(range(2, 18)) if wrong_config else []) + ([19] if wrong_command else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["send", "fetch", "backup"]:
        return None
    if argv[1] == "backup":
        return {"action": "backup"}
    if argv[1] == "fetch":
        account = next((v[v.index("=") + 1 :] for v in argv[2:] if v.startswith("account=")), None)
        invalid = [v for v in argv[2:] if not v.startswith("account=")]
        if invalid:
            raise SMException(f"Invalid options for fetch: {'  ;  '.join(invalid)}")
        return {"action": "fetch", "account": account}
    allowed_opts = ["recipient", "subject", "body", "file", "account"]
    mandatory_opts = ["recipient", "subject", "body"]
    invalid_options = [v for v in argv[2:] if all(not v.startswith(f"{o}=") for o in allowed_opts)]
    if invalid_options:
        raise SMException(f"Invalid options for send: {'  ;  '.join(invalid_options)}")
    single_opts = ("recipient=", "subject=", "body=", "account=")
    opts = {v[: v.index("=")]: v[v.index("=") + 1 :] for v in argv[2:] if v.startswith(single_opts)}
    missing_options = [v for v in mandatory_opts if v not in opts]
    if missing_options:
        raise SMException(f"Missing options for send: {'  ;  '.join(missing_options)}")
    opts["files"] = [v[v.index("=") + 1 :] for v in argv[2:] if v.startswith("file=")]
    opts.setdefault("account", None)
    return {**opts, "action": "send"}


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
        try:
            selected_account = [m for m in mail_connections_infos if m.name == account_name][0]
        except IndexError:
            raise SMException(f"Account named {account_name} not found") from None
        send_email(selected_account, args["recipient"], args["subject"], args["body"], args["files"])
    elif args["action"] == "fetch":
        if args["account"]:
            try:
                accounts = [m for m in mail_connections_infos if m.name == args["account"]]
                if not accounts:
                    raise IndexError
            except IndexError:
                raise SMException(f"Account named {args['account']} not found") from None
        else:
            accounts = mail_connections_infos
        for account in accounts:
            fetch_emails(account)
    elif args["action"] == "backup":
        quick_and_dirty_backup(config)  # TODO Better implem obviously
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
