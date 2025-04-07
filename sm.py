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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from enum import Enum
from json import loads
from hashlib import sha256
from pathlib import Path
from smtplib import SMTP, SMTPAuthenticationError
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
from sys import argv, flags as sys_flags


colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


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


def send_email(account_config, recipient_email, subject, body, attachment_paths=None):
    sender_email = account_config.username
    message = MIMEMultipart()
    for k, v in {"From": sender_email, "To": recipient_email, "Subject": subject}.items():
        message[k] = v
    message.attach(MIMEText(body, "plain"))
    if attachment_paths:
        for file_path in attachment_paths:
            try:
                with open(file_path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                filename = os.path.basename(file_path)
                part.add_header("Content-Disposition", f"attachment; filename= {filename}")
                message.attach(part)
                
            except Exception as e:
                raise SMException(f"Error attaching file {file_path}: {str(e)}") from e

    try:
        ssl_context=make_pinned_ssl_context(account_config.pinned_smtp_certificate_sha256)
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
        raise SMException(f"Error sending email:\n{str(exc)}") from exc
    finally:
        try:
            server.quit()
        except:
            pass


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    output_lines = [
        "sm - Simple Mail client",
        "=======================",
        """~/.config/sm/init.json => {"accounts": [ACCOUNT_INFOS, ACCOUNT_INFOS, ...]}""",
        "  - ACCOUNT_INFOS = {",
        "    \"name\": \"XX\"",
        "    \"imap_ssl_host\": \"XX\"",
        "    \"imap_ssl_port\": 993",
        "    \"username\": \"XX\"",
        "    \"password\": \"XX\"",
        "    \"pinned_imap_certificate_sha256\": \"XX\"",
        "    \"smtp_ssl_host\": \"XX\"",
        "    \"smtp_ssl_port\": 587",
        "    \"pinned_smtp_certificate_sha256\": \"XX\"",
        "    \"local_store_path\": \"XX\""
        "=======================",
        "- sm send recipient=c4ffein@gmail.com subject=title body=something file=/optional/path ==> send a mail",
        "=======================",
        "You need to generate an app specific password for gmail or other mail clients" 
    ]
    red_indexes = (list(range(2, 14)) if wrong_config else []) + ([15] if wrong_command or wrong_arg_len else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] != "send":
        return None
    allowed_opts = ["recipient", "subject", "body", "file"]
    mandatory_opts = ["recipient", "subject", "body"]
    invalid_options = [v for v in argv[2:] if all(not v.startswith(f"{o}=") for o in allowed_opts)]
    if invalid_options:
        raise SMException(f"Invalid options for send: {'  ;  '.join(invalid_options)}")
    opts = {v[:v.index("=")]: v[v.index("=")+1:] for v in argv[2:] if not v.startswith("file=")}
    missing_options = [v for v in mandatory_opts if v not in opts]
    if missing_options:
        raise SMException(f"Missing options for send: {'  ;  '.join(missing_options)}")
    opts["files"] = [v[v.index("=")+1:] for v in argv[2:] if v.startswith("file=")]
    return opts


def main():
    try:
        with (Path.home() / ".config" / "sm" / "config.json").open() as f:
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
    send_email(selected_account, args["recipient"], args["subject"], args["body"], args["files"])
    return


if __name__ == "__main__":
    try:
        exit(main())
    except SMException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
