#!/usr/bin/env python

"""
sm - Simple Mail client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
TODOs and possible improvements: Fill this
TODO Linter in CI
"""

import os
from email import encoders, message_from_bytes
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from hashlib import sha256
from imaplib import IMAP4_SSL
from itertools import chain
from json import loads
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


def make_pinned_ssl_context(pinned_sha_256):
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

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
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
            r = func(*args, **kwargs)
        except SMException as exc:
            release_lock()
            raise exc
        release_lock()
        return r

    return wrapper


class MailConnectionInfos:
    KWARGS = {
        "name": None,
        "imap_ssl_host": None,
        "imap_ssl_port": None,
        "pinned_imap_certificate_sha256": None,
        "smtp_ssl_host": None,
        "smtp_ssl_port": None,
        "pinned_smtp_certificate_sha256": None,
        "username": None,
        "password": None,
        "local_store_path": None,
    }

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self.KWARGS:
                raise SMException(f"Wrong argument for account in config: {k}")
            setattr(self, k, v)


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


def search_uid_string(uid_max, criteria):
    c = list((t0, f"\"{t1}\"") for t0, t1 in criteria.items()) + [("UID", f"{uid_max+1}:*")]
    return f"({' '.join(chain(*c))})"


@raise_smexception_on_connection_error
def quick_and_dirty_backup(config):
    # TODO Better login/logout, gracefully fail for any error
    criteria = {}
    uid_max = 0
    connection_infos = MailConnectionInfos(**config["accounts"][1])  # TODO Parameterize 1, reuse parameter
    ssl_context = make_pinned_ssl_context(connection_infos.pinned_imap_certificate_sha256)
    mail = IMAP4_SSL(connection_infos.imap_ssl_host, connection_infos.imap_ssl_port, ssl_context=ssl_context)
    mail.login(connection_infos.username, connection_infos.password)
    status, messages = mail.select("inbox")  # TODO Operate on all folders
    result, data = mail.uid("SEARCH", None, search_uid_string(uid_max, criteria))
    uids = [int(s) for s in data[0].split()]
    print(uids)  # TODO Aggregate and log
    if uids:
        uid_max = max(uids)

    for xii, uid in enumerate(uids):
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
                    email_identifier = response_part[0]
                    email_data = message_from_bytes(response_part[1])
                    save_attachment(Path(config["accounts"][1]["local_store_path"]), email_data)  # TODO Parameterize 1
                    print(response_part[1], email_data.get_payload())  # TODO Better than naive print
                    # TODO Handle save_at in response_part[1] to compute file name instead?
            uid_max = uid
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
        ssl_context = make_pinned_ssl_context(account_config.pinned_smtp_certificate_sha256)
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


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    output_lines = [
        "sm - Simple Mail client",
        "───────────────────────",
        """~/.config/sm/init.json ──➤ {"accounts": [ACCOUNT_INFOS, ACCOUNT_INFOS, ...]}""",
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
        "───────────────────────",
        "- sm send recipient=c4ffein@gmail.com subject=title body=something file=/optional/path ──➤ send a mail",
        "- sm backup                                                                            ──➤ backup everything",
        "───────────────────────",
        "You need to generate an app specific password for gmail or other mail clients",
    ]
    red_indexes = (list(range(2, 14)) if wrong_config else []) + ([15] if wrong_command or wrong_arg_len else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["send", "backup"]:
        return None
    if argv[1] == "backup":
        if len(argv) < 2:
            return None
        return {"action": "backup"}
    allowed_opts = ["recipient", "subject", "body", "file"]
    mandatory_opts = ["recipient", "subject", "body"]
    invalid_options = [v for v in argv[2:] if all(not v.startswith(f"{o}=") for o in allowed_opts)]
    if invalid_options:
        raise SMException(f"Invalid options for send: {'  ;  '.join(invalid_options)}")
    opts = {v[: v.index("=")]: v[v.index("=") + 1 :] for v in argv[2:] if not v.startswith("file=")}
    missing_options = [v for v in mandatory_opts if v not in opts]
    if missing_options:
        raise SMException(f"Missing options for send: {'  ;  '.join(missing_options)}")
    opts["files"] = [v[v.index("=") + 1 :] for v in argv[2:] if v.startswith("file=")]
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
        mail_connections_infos = [MailConnectionInfos(**s) for s in config["accounts"]]
    except Exception:
        return usage(wrong_config=True)
    main_infos = "gmail"  # TODO Adapt
    try:
        selected_account = [m for m in mail_connections_infos if m.name == main_infos][0]
    except Exception as exc:
        raise SMException(f"Account named {main_infos} not found") from exc
    args = consume_args()
    if not args:
        return usage()
    if args["action"] == "send":
        send_email(selected_account, args["recipient"], args["subject"], args["body"], args["files"])
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
