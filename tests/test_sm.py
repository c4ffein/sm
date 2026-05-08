"""Tests for sm. Run from repo root: python3 -m unittest discover tests"""
import hashlib
import io
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from email import message_from_bytes
from email.message import EmailMessage
from pathlib import Path

import sm
from sm import (
    Context,
    ErrorEvent,
    MailConnectionInfos,
    Param,
    SMException,
    Store,
    Verbosity,
    _is_safe_folder_name,
    build_email_message,
    consume_args,
    decode_modified_utf7,
    internaldate_key,
    kiss_extract_text_from_eml,
    list_attachments,
    parse_list_response,
    safe_str,
    save_attachment_bytes,
    send_email,
)


class TestParam(unittest.TestCase):
    def test_default_verbosity_is_error(self):
        self.assertEqual(Param().verbosity, Verbosity.ERROR)


class TestContext(unittest.TestCase):
    def test_default_param_and_errors(self):
        c = Context()
        self.assertEqual(c.param.verbosity, Verbosity.ERROR)
        self.assertEqual(c.errors, [])

    def test_log_at_or_below_verbosity_prints(self):
        c = Context(param=Param(verbosity=Verbosity.DEBUG))
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.log("info msg", Verbosity.INFO)
            c.log("debug msg", Verbosity.DEBUG)
        out = buf.getvalue()
        self.assertIn("info msg", out)
        self.assertIn("debug msg", out)

    def test_log_above_verbosity_silent(self):
        c = Context(param=Param(verbosity=Verbosity.ERROR))
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.log("info msg", Verbosity.INFO)
            c.log("debug msg", Verbosity.DEBUG)
        self.assertEqual(buf.getvalue(), "")

    def test_log_default_level_is_info(self):
        c = Context(param=Param(verbosity=Verbosity.ERROR))
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.log("hello")
        self.assertEqual(buf.getvalue(), "")  # ERROR < INFO, silent

    def test_record_error_appends(self):
        c = Context()
        c.record_error("parse_list", "bogus item")
        self.assertEqual(len(c.errors), 1)
        self.assertEqual(c.errors[0], ErrorEvent(kind="parse_list", detail="bogus item", raw=None))

    def test_record_error_carries_raw(self):
        c = Context()
        c.record_error("select_failed", "SELECT returned NO", raw=b"some raw bytes")
        self.assertEqual(c.errors[0].raw, b"some raw bytes")

    def test_record_error_accumulates(self):
        c = Context()
        c.record_error("parse_list", "first")
        c.record_error("select_failed", "second")
        c.record_error("parse_list", "third")
        self.assertEqual([e.kind for e in c.errors], ["parse_list", "select_failed", "parse_list"])

    def test_separate_contexts_are_isolated(self):
        # field(default_factory=list) — each Context gets its own list, not a shared default.
        a = Context()
        b = Context()
        a.record_error("x", "to a")
        self.assertEqual(b.errors, [])


class TestConsumeArgs(unittest.TestCase):
    def test_empty_argv(self):
        action, ctx = consume_args(["sm"])
        self.assertIsNone(action)
        self.assertEqual(ctx.param.verbosity, Verbosity.ERROR)

    def test_unknown_command(self):
        action, _ = consume_args(["sm", "fubar"])
        self.assertIsNone(action)

    def test_sync_minimal(self):
        action, ctx = consume_args(["sm", "sync"])
        self.assertEqual(action, {"action": "sync", "account": None, "auto_apply": False})
        self.assertEqual(ctx.param.verbosity, Verbosity.ERROR)

    def test_sync_with_account_and_yes(self):
        action, _ = consume_args(["sm", "sync", "account=foo", "yes"])
        self.assertEqual(action["account"], "foo")
        self.assertTrue(action["auto_apply"])

    def test_sync_invalid_option(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "sync", "garbage=x"])

    def test_verbose_numeric(self):
        for raw, level in [("0", Verbosity.ERROR), ("1", Verbosity.INFO), ("2", Verbosity.DEBUG)]:
            with self.subTest(raw=raw):
                _, ctx = consume_args(["sm", "sync", f"verbose={raw}"])
                self.assertEqual(ctx.param.verbosity, level)

    def test_verbose_named(self):
        for raw, level in [
            ("error", Verbosity.ERROR),
            ("info", Verbosity.INFO),
            ("debug", Verbosity.DEBUG),
            ("DEBUG", Verbosity.DEBUG),  # case-insensitive
        ]:
            with self.subTest(raw=raw):
                _, ctx = consume_args(["sm", "sync", f"verbose={raw}"])
                self.assertEqual(ctx.param.verbosity, level)

    def test_verbose_invalid(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "sync", "verbose=loud"])

    def test_verbose_last_wins(self):
        _, ctx = consume_args(["sm", "sync", "verbose=0", "verbose=2"])
        self.assertEqual(ctx.param.verbosity, Verbosity.DEBUG)

    def test_read_minimal(self):
        action, _ = consume_args(["sm", "read"])
        self.assertEqual(action, {"action": "read", "account": None})

    def test_read_with_account(self):
        action, _ = consume_args(["sm", "read", "account=work"])
        self.assertEqual(action["account"], "work")

    def test_read_invalid_option(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "read", "yes"])  # yes is sync-only

    def test_send_minimal(self):
        action, _ = consume_args(["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello"])
        self.assertEqual(action["action"], "send")
        self.assertEqual(action["recipients"], ["a@b.c"])
        self.assertEqual(action["subject"], "hi")
        self.assertEqual(action["body"], "hello")
        self.assertEqual(action["files"], [])
        self.assertIsNone(action["account"])

    def test_send_multiple_recipients(self):
        action, _ = consume_args(
            ["sm", "send", "recipient=a@b.c", "recipient=d@e.f", "subject=hi", "body=hello"]
        )
        self.assertEqual(action["recipients"], ["a@b.c", "d@e.f"])

    def test_send_multiple_files(self):
        action, _ = consume_args(
            ["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello", "file=/tmp/x", "file=/tmp/y"]
        )
        self.assertEqual(action["files"], ["/tmp/x", "/tmp/y"])

    def test_send_with_account(self):
        action, _ = consume_args(
            ["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello", "account=work"]
        )
        self.assertEqual(action["account"], "work")

    def test_send_missing_recipient(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "send", "subject=hi", "body=hello"])

    def test_send_missing_subject(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "send", "recipient=a@b.c", "body=hello"])

    def test_send_missing_body(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "send", "recipient=a@b.c", "subject=hi"])

    def test_send_invalid_option(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello", "bogus=x"])


class TestSafeStr(unittest.TestCase):
    def test_ascii_passthrough(self):
        self.assertEqual(safe_str("Hello, world!"), "Hello, world!")

    def test_control_char_replaced(self):
        self.assertEqual(safe_str("a\x07b"), "a\ufffdb")

    def test_ansi_escape_sequence_replaced(self):
        # ESC byte becomes replacement; the rest of the sequence (ASCII) survives.
        self.assertEqual(safe_str("a\x1b[31mb"), "a\ufffd[31mb")

    def test_newlines_default_allowed(self):
        self.assertEqual(safe_str("a\nb\rc"), "a\nb\rc")

    def test_newlines_blocked(self):
        self.assertEqual(safe_str("a\nb\rc", allow_newlines=False), "a\ufffdb\ufffdc")

    def test_tab_allowed(self):
        self.assertEqual(safe_str("a\tb"), "a\tb")

    def test_non_string_coerced(self):
        self.assertEqual(safe_str(42), "42")


class TestMailConnectionInfos(unittest.TestCase):
    def test_from_dict_valid(self):
        info = MailConnectionInfos.from_dict({"name": "work", "username": "u"})
        self.assertEqual(info.name, "work")
        self.assertEqual(info.username, "u")

    def test_from_dict_extra_key_raises(self):
        with self.assertRaises(SMException):
            MailConnectionInfos.from_dict({"name": "x", "bogus_field": "y"})

    def test_from_dict_empty(self):
        info = MailConnectionInfos.from_dict({})
        self.assertIsNone(info.name)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmp.name)
        self._orig_lock = sm.LOCK_PATH
        sm.LOCK_PATH = self.tmppath / "lock"
        Store._active = False  # defensive: previous failure may have left it set

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        Store._active = False
        self.tmp.cleanup()

    def test_enter_creates_mails_dir_and_lock(self):
        with Store(self.tmppath / "store"):
            self.assertTrue((self.tmppath / "store" / "mails").is_dir())
            self.assertTrue(sm.LOCK_PATH.exists())
        self.assertFalse(sm.LOCK_PATH.exists())

    def test_save_index_roundtrips(self):
        with Store(self.tmppath / "store") as store:
            store.index["abc"] = {"subject": "test"}
            store.save_index()
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.index, {"abc": {"subject": "test"}})

    def test_load_index_missing_file(self):
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.index, {})

    def test_load_index_empty_file(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text("")
        with Store(store_path) as store:
            self.assertEqual(store.index, {})

    def test_load_index_whitespace_only(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text("   \n  ")
        with Store(store_path) as store:
            self.assertEqual(store.index, {})

    def test_nested_context_raises(self):
        with Store(self.tmppath / "store"):
            with self.assertRaises(SMException):
                with Store(self.tmppath / "store2"):
                    pass

    def test_lock_file_collision_raises(self):
        sm.LOCK_PATH.touch()
        with self.assertRaises(SMException):
            with Store(self.tmppath / "store"):
                pass
        # Stale lock not removed by failed acquire — that's the intended UX.
        self.assertTrue(sm.LOCK_PATH.exists())

    def test_save_index_outside_context_raises(self):
        store = Store(self.tmppath / "store")
        with self.assertRaises(SMException):
            store.save_index()

    def test_save_index_atomic_no_partial_file(self):
        # After save_index, the temp file should be gone (rename moved it).
        store_path = self.tmppath / "store"
        with Store(store_path) as store:
            store.index["abc"] = {"subject": "test"}
            store.save_index()
            self.assertFalse((store_path / ".index.json.tmp").exists())
            self.assertTrue((store_path / "index.json").exists())


class TestInternaldateKey(unittest.TestCase):
    def test_parses_imap_format(self):
        # IMAP INTERNALDATE format: dd-MMM-yyyy HH:MM:SS +zzzz
        dt = internaldate_key({"internaldate": "08-May-2026 14:30:00 +0000"})
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 5)
        self.assertEqual(dt.day, 8)
        self.assertIsNotNone(dt.tzinfo)

    def test_normalizes_to_aware(self):
        # Every returned datetime must be tz-aware so sorting can't blow up.
        for raw in ["08-May-2026 14:30:00 +0000", "08-May-2026 14:30:00 -0500", ""]:
            with self.subTest(raw=raw):
                dt = internaldate_key({"internaldate": raw})
                self.assertIsNotNone(dt.tzinfo)

    def test_missing_internaldate_returns_epoch(self):
        dt = internaldate_key({})
        self.assertEqual(dt, sm._EPOCH)

    def test_garbage_internaldate_returns_epoch(self):
        dt = internaldate_key({"internaldate": "not a date at all"})
        self.assertEqual(dt, sm._EPOCH)

    def test_does_not_use_date_header(self):
        # Sort key is internaldate-only — Date: header must be ignored.
        dt = internaldate_key({"date": "Thu, 8 May 2026 14:30:00 +0000"})
        self.assertEqual(dt, sm._EPOCH)

    def test_chronological_sort(self):
        entries = [
            {"internaldate": "01-Jan-2024 00:00:00 +0000"},
            {"internaldate": "15-Dec-2025 12:00:00 +0000"},
            {"internaldate": "08-May-2026 14:30:00 +0000"},
            {},  # epoch — sorts last when reverse=True (i.e. oldest)
        ]
        ordered = sorted(entries, key=internaldate_key, reverse=True)
        self.assertEqual(ordered[0]["internaldate"], "08-May-2026 14:30:00 +0000")
        self.assertEqual(ordered[1]["internaldate"], "15-Dec-2025 12:00:00 +0000")
        self.assertEqual(ordered[2]["internaldate"], "01-Jan-2024 00:00:00 +0000")
        self.assertEqual(ordered[3], {})

    def test_mixed_timezones_sort_by_instant(self):
        # 14:00 UTC < 10:00 -0500 (= 15:00 UTC). Sort must respect the instant, not wall-clock.
        a = {"internaldate": "08-May-2026 14:00:00 +0000"}
        b = {"internaldate": "08-May-2026 10:00:00 -0500"}
        ordered = sorted([a, b], key=internaldate_key, reverse=True)
        self.assertEqual(ordered[0], b)


class TestKissExtractTextFromEml(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_msg(self, msg):
        path = self.tmppath / "x.eml"
        path.write_bytes(msg.as_bytes())
        return path

    def test_prefer_plain_over_html(self):
        msg = EmailMessage()
        msg["Subject"] = "hi"
        msg.set_content("plain version")
        msg.add_alternative("<p>html version</p>", subtype="html")
        text = kiss_extract_text_from_eml(self._write_msg(msg))
        self.assertIn("plain version", text)
        self.assertNotIn("html version", text)

    def test_html_only_fallback(self):
        msg = EmailMessage()
        msg["Subject"] = "hi"
        msg.set_content("<p>html only</p><br>line2", subtype="html")
        text = kiss_extract_text_from_eml(self._write_msg(msg))
        self.assertIn("html only", text)
        self.assertIn("line2", text)
        self.assertNotIn("<p>", text)
        self.assertNotIn("<br>", text)

    def test_html_entity_unescaped(self):
        msg = EmailMessage()
        msg.set_content("<p>5 &lt; 10</p>", subtype="html")
        text = kiss_extract_text_from_eml(self._write_msg(msg))
        self.assertIn("5 < 10", text)

    def test_no_text_content(self):
        # Hand-built RFC822 with only an octet-stream part.
        path = self.tmppath / "binary.eml"
        path.write_bytes(
            b"From: a@b.c\r\n"
            b"Subject: empty\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
            b"\x00\x01\x02"
        )
        self.assertEqual(kiss_extract_text_from_eml(path), "(no text content)")


class TestListAttachments(unittest.TestCase):
    def test_empty_when_no_attachments(self):
        msg = EmailMessage()
        msg.set_content("just a body")
        self.assertEqual(list_attachments(msg), [])

    def test_returns_filename_and_content(self):
        msg = EmailMessage()
        msg.set_content("body")
        msg.add_attachment(b"hello world", maintype="application", subtype="octet-stream", filename="hi.txt")
        atts = list_attachments(msg)
        self.assertEqual(len(atts), 1)
        name, content = atts[0]
        self.assertEqual(name, "hi.txt")
        self.assertEqual(content, b"hello world")

    def test_multiple_attachments_preserve_order(self):
        msg = EmailMessage()
        msg.set_content("body")
        msg.add_attachment(b"first", maintype="application", subtype="octet-stream", filename="a.bin")
        msg.add_attachment(b"second", maintype="application", subtype="octet-stream", filename="b.bin")
        atts = list_attachments(msg)
        self.assertEqual([n for n, _ in atts], ["a.bin", "b.bin"])

    def test_skips_parts_without_filename(self):
        # Plain text body has no filename; should not appear.
        msg = EmailMessage()
        msg.set_content("plain body")
        msg.add_alternative("<p>html</p>", subtype="html")
        msg.add_attachment(b"bytes", maintype="application", subtype="pdf", filename="x.pdf")
        atts = list_attachments(msg)
        self.assertEqual(len(atts), 1)
        self.assertEqual(atts[0][0], "x.pdf")


class TestSaveAttachmentBytes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_file(self):
        target = save_attachment_bytes(b"payload", self.tmppath, "doc.pdf")
        self.assertEqual(target, self.tmppath / "doc.pdf")
        self.assertEqual(target.read_bytes(), b"payload")

    def test_creates_missing_parent_dirs(self):
        nested = self.tmppath / "a" / "b" / "c"
        target = save_attachment_bytes(b"x", nested, "f.txt")
        self.assertTrue(target.exists())
        self.assertTrue(nested.is_dir())

    def test_collision_appends_suffix(self):
        save_attachment_bytes(b"first", self.tmppath, "doc.pdf")
        target = save_attachment_bytes(b"second", self.tmppath, "doc.pdf")
        self.assertEqual(target.name, "doc_1.pdf")
        self.assertEqual(target.read_bytes(), b"second")
        # Original untouched.
        self.assertEqual((self.tmppath / "doc.pdf").read_bytes(), b"first")

    def test_collision_increments_until_free(self):
        save_attachment_bytes(b"a", self.tmppath, "x.txt")
        save_attachment_bytes(b"b", self.tmppath, "x.txt")
        save_attachment_bytes(b"c", self.tmppath, "x.txt")
        names = sorted(p.name for p in self.tmppath.iterdir())
        self.assertEqual(names, ["x.txt", "x_1.txt", "x_2.txt"])

    def test_spaces_become_underscores(self):
        target = save_attachment_bytes(b"x", self.tmppath, "my invoice.pdf")
        self.assertEqual(target.name, "my_invoice.pdf")

    def test_path_separators_replaced(self):
        # Path-traversal attempt: "/" → "_". Leading dot prefixed with "_" (no hidden file in destination).
        target = save_attachment_bytes(b"x", self.tmppath, "../etc/passwd")
        self.assertEqual(target.parent, self.tmppath)
        self.assertEqual(target.name, "_.._etc_passwd")
        self.assertNotIn("/", target.name)

    def test_disallowed_chars_become_underscore(self):
        target = save_attachment_bytes(b"x", self.tmppath, "hello@world!.pdf")
        self.assertEqual(target.name, "hello_world_.pdf")

    def test_leading_dot_gets_underscore_prefix(self):
        # No hidden files in the destination — original name stays visible.
        target = save_attachment_bytes(b"x", self.tmppath, ".bashrc")
        self.assertEqual(target.name, "_.bashrc")

    def test_multiple_leading_dots_get_single_prefix(self):
        target = save_attachment_bytes(b"x", self.tmppath, "..foo")
        self.assertEqual(target.name, "_..foo")

    def test_mid_string_dots_preserved(self):
        target = save_attachment_bytes(b"x", self.tmppath, "archive.tar.gz")
        self.assertEqual(target.name, "archive.tar.gz")

    def test_dot_only_name_falls_back_to_attachment(self):
        for raw in ["..", ".", "..."]:
            with self.subTest(raw=raw):
                # Fresh dir per case so collision logic doesn't kick in.
                d = self.tmppath / raw.replace(".", "d")
                d.mkdir()
                target = save_attachment_bytes(b"x", d, raw)
                self.assertEqual(target.name, "attachment")

    def test_all_disallowed_chars_falls_back_to_attachment(self):
        target = save_attachment_bytes(b"x", self.tmppath, "????")
        self.assertEqual(target.name, "attachment")

    def test_returns_path_object(self):
        target = save_attachment_bytes(b"x", self.tmppath, "f.txt")
        self.assertIsInstance(target, Path)


class TestDecodeModifiedUTF7(unittest.TestCase):
    def test_pure_ascii_passthrough(self):
        self.assertEqual(decode_modified_utf7(b"INBOX"), "INBOX")
        self.assertEqual(decode_modified_utf7(b"[Gmail]/Sent Mail"), "[Gmail]/Sent Mail")

    def test_empty(self):
        self.assertEqual(decode_modified_utf7(b""), "")

    def test_literal_ampersand(self):
        # &- encodes a literal "&"
        self.assertEqual(decode_modified_utf7(b"&-"), "&")
        self.assertEqual(decode_modified_utf7(b"M&-M"), "M&M")

    def test_single_non_ascii_char(self):
        # ä = U+00E4 → UTF-16BE 00 E4 → base64 "AOQ" → wrapped "&AOQ-"
        self.assertEqual(decode_modified_utf7(b"&AOQ-"), "ä")

    def test_word_with_non_ascii(self):
        # é = U+00E9 → "AOk"
        self.assertEqual(decode_modified_utf7(b"Caf&AOk-"), "Café")

    def test_multiple_codepoints_in_one_escape(self):
        # 日本 = U+65E5 U+672C → UTF-16BE 65 E5 67 2C → base64 "ZeVnLA"
        # (ZeU = 65 E5; ZeVnLA = 65 E5 67 2C)
        self.assertEqual(decode_modified_utf7(b"&ZeVnLA-"), "日本")

    def test_modified_base64_uses_comma_for_slash(self):
        # U+FF00 → UTF-16BE FF 00 → standard base64 "/wA" → modified ",wA"
        self.assertEqual(decode_modified_utf7(b"&,wA-"), "＀")

    def test_unterminated_escape_falls_back_literal(self):
        # No closing '-' — emit verbatim, do not raise.
        self.assertEqual(decode_modified_utf7(b"&AOQ"), "&AOQ")

    def test_malformed_base64_falls_back_literal(self):
        # Garbage payload — emit verbatim.
        self.assertEqual(decode_modified_utf7(b"&!!!-"), "&!!!-")

    def test_non_bytes_returns_empty(self):
        self.assertEqual(decode_modified_utf7("INBOX"), "")
        self.assertEqual(decode_modified_utf7(None), "")


class TestParseListResponse(unittest.TestCase):
    def test_standard_quoted(self):
        entry = parse_list_response(b'(\\HasNoChildren) "/" "INBOX"')
        self.assertEqual(entry.flags, frozenset({"\\HasNoChildren"}))
        self.assertEqual(entry.delim, "/")
        self.assertEqual(entry.name, "INBOX")
        self.assertEqual(entry.name_for_select, "INBOX")

    def test_multiple_flags(self):
        entry = parse_list_response(b'(\\Noselect \\HasChildren) "/" "[Gmail]"')
        self.assertEqual(entry.flags, frozenset({"\\Noselect", "\\HasChildren"}))
        self.assertEqual(entry.name, "[Gmail]")

    def test_empty_flags(self):
        entry = parse_list_response(b'() "/" "Foo"')
        self.assertEqual(entry.flags, frozenset())

    def test_nil_delimiter(self):
        entry = parse_list_response(b'() NIL "Trash"')
        self.assertIsNone(entry.delim)
        self.assertEqual(entry.name, "Trash")

    def test_atom_mailbox_name(self):
        # Unquoted (atom) form — legal per spec.
        entry = parse_list_response(b'() "/" INBOX')
        self.assertEqual(entry.name, "INBOX")
        self.assertEqual(entry.name_for_select, "INBOX")

    def test_quoted_name_with_spaces(self):
        entry = parse_list_response(b'() "/" "Sent Items"')
        self.assertEqual(entry.name, "Sent Items")

    def test_modified_utf7_name(self):
        entry = parse_list_response(b'() "/" "Caf&AOk-"')
        self.assertEqual(entry.name, "Café")
        # name_for_select retains the wire form so SELECT round-trips unchanged.
        self.assertEqual(entry.name_for_select, "Caf&AOk-")

    def test_escaped_quote_in_name_now_rejected(self):
        # Pre-safety-check this returned a ListEntry with name='weird"name'. Now the parser
        # refuses any name byte that would break SELECT quoting.
        ctx = Context()
        self.assertIsNone(parse_list_response(b'() "/" "weird\\"name"', ctx))
        self.assertIn("disallowed byte 0x22", ctx.errors[0].detail)

    def test_escaped_delim(self):
        # Backslash-escaped delimiter char.
        entry = parse_list_response(b'() "\\\\" "Foo"')
        self.assertEqual(entry.delim, "\\")
        self.assertEqual(entry.name, "Foo")

    def test_literal_form_as_tuple(self):
        # imaplib delivers literals as a tuple: (header_with_{N}, literal_bytes).
        entry = parse_list_response((b'(\\HasNoChildren) "/" {7}', b"INBOX/x"))
        self.assertEqual(entry.name, "INBOX/x")
        self.assertEqual(entry.name_for_select, "INBOX/x")

    def test_literal_with_crlf_between_marker_and_bytes(self):
        # Some servers/parsers leave the CRLF between the {N} marker and the literal bytes.
        entry = parse_list_response(b'(\\HasNoChildren) "/" {7}\r\nINBOX/y')
        self.assertEqual(entry.name, "INBOX/y")

    def test_literal_with_modified_utf7(self):
        # Literal carrying a non-ASCII (mod-UTF-7) name.
        entry = parse_list_response((b'() "/" {8}', b"Caf&AOk-"))
        self.assertEqual(entry.name, "Café")
        self.assertEqual(entry.name_for_select, "Caf&AOk-")

    def test_garbage_returns_none(self):
        for raw in [b"totally bogus", b"(no closing", b"", b"() not_a_delim INBOX"]:
            with self.subTest(raw=raw):
                self.assertIsNone(parse_list_response(raw))

    def test_non_bytes_input_returns_none(self):
        self.assertIsNone(parse_list_response("string instead of bytes"))
        self.assertIsNone(parse_list_response(None))
        self.assertIsNone(parse_list_response(42))

    def test_failures_record_specific_reasons_on_ctx(self):
        # Each failure mode tags the ErrorEvent.detail with a distinct reason.
        cases = [
            (b"totally bogus",            "no opening paren"),
            (b"(no closing",              "unterminated flag list"),
            (b"() not_a_delim INBOX",     "expected delimiter"),
            (b"() NIL",                   "missing mailbox name"),
            (b'() "/" "unterminated',     "unterminated quoted mailbox name"),
            (b'() "/" {abc}',             "non-numeric literal length"),
            (b'() "/" {99}\r\nshort',     "literal length exceeds available bytes"),
            (b'() "/" {bogus',            "malformed literal length marker"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                ctx = Context()
                self.assertIsNone(parse_list_response(raw, ctx))
                self.assertEqual(len(ctx.errors), 1)
                self.assertEqual(ctx.errors[0].kind, "parse_list")
                self.assertIn(expected, ctx.errors[0].detail)
                self.assertEqual(ctx.errors[0].raw, raw.strip())

    def test_non_bytes_input_records_with_repr(self):
        ctx = Context()
        self.assertIsNone(parse_list_response(42, ctx))
        self.assertEqual(ctx.errors[0].kind, "parse_list")
        self.assertIn("non-bytes/tuple", ctx.errors[0].detail)
        # raw stores a repr() of the bad input so future-you can identify what came in.
        self.assertEqual(ctx.errors[0].raw, b"42")

    def test_success_does_not_touch_ctx(self):
        ctx = Context()
        entry = parse_list_response(b'(\\HasNoChildren) "/" "INBOX"', ctx)
        self.assertIsNotNone(entry)
        self.assertEqual(ctx.errors, [])

    def test_ctx_optional_default_none(self):
        # Backward compat: existing call sites that don't pass ctx still get None on garbage.
        self.assertIsNone(parse_list_response(b"garbage"))
        # And no record is attempted (would AttributeError if ctx were used unconditionally).

    def test_rejects_name_with_unsafe_byte(self):
        # Literal form lets a hostile/buggy server send a name with bytes that would break
        # SELECT quoting. Parser refuses with a byte-specific reason.
        # Trailing 'X' protects the literal bytes from raw.strip().
        # 7 bytes: I N B O X \r X
        ctx = Context()
        self.assertIsNone(parse_list_response(b'() "/" {7}\r\nINBOX\rX', ctx))
        self.assertEqual(ctx.errors[0].kind, "parse_list")
        self.assertIn("disallowed byte 0x0d", ctx.errors[0].detail)  # CR

    def test_rejects_name_with_quote_byte(self):
        # Backslash-escaped quote is unescaped into the name bytes — would break f'"{name}"'.
        ctx = Context()
        self.assertIsNone(parse_list_response(b'() "/" "evil\\"name"', ctx))
        self.assertIn("disallowed byte 0x22", ctx.errors[0].detail)  # "

    def test_rejects_name_with_high_bit(self):
        # Modified UTF-7 names are pure ASCII per spec; high-bit byte must be refused.
        ctx = Context()
        self.assertIsNone(parse_list_response(b'() "/" {1}\r\n\xff', ctx))
        self.assertIn("disallowed byte 0xff", ctx.errors[0].detail)


class TestIsSafeFolderName(unittest.TestCase):
    def test_accepts_typical_names(self):
        for name in ["INBOX", "[Gmail]/All Mail", "Sent Items", "Receipts/Caf&AOk-", "a-b_c.d"]:
            with self.subTest(name=name):
                self.assertTrue(_is_safe_folder_name(name))

    def test_rejects_quote(self):
        self.assertFalse(_is_safe_folder_name('evil"name'))

    def test_rejects_backslash(self):
        self.assertFalse(_is_safe_folder_name("evil\\name"))

    def test_rejects_cr_lf(self):
        self.assertFalse(_is_safe_folder_name("INBOX\r\n"))
        self.assertFalse(_is_safe_folder_name("INBOX\nA1 DELETE INBOX"))

    def test_rejects_control_chars(self):
        for c in ("\x00", "\x07", "\x1b", "\x7f"):
            with self.subTest(c=repr(c)):
                self.assertFalse(_is_safe_folder_name(f"a{c}b"))

    def test_rejects_high_bit(self):
        # Even legitimate UTF-8 chars are out — names on the wire must be modified UTF-7 (ASCII only).
        self.assertFalse(_is_safe_folder_name("Café"))

    def test_empty_is_safe(self):
        # Empty string passes the per-byte check (no bytes to fail on). The parser rejects empty
        # atom names separately; this predicate is purely about character safety.
        self.assertTrue(_is_safe_folder_name(""))


class TestBuildEmailMessage(unittest.TestCase):
    def test_basic_headers(self):
        msg = build_email_message("me@example.com", ["a@b.c"], "hello", "body")
        self.assertEqual(msg["From"], "me@example.com")
        self.assertEqual(msg["To"], "a@b.c")
        self.assertEqual(msg["Subject"], "hello")

    def test_multiple_recipients_joined_with_comma(self):
        msg = build_email_message("me@x", ["a@b.c", "d@e.f"], "s", "b")
        self.assertEqual(msg["To"], "a@b.c, d@e.f")

    def test_body_is_text_plain(self):
        msg = build_email_message("me@x", ["a@b.c"], "s", "the body")
        # Walk to find text/plain part
        text = None
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                text = part.get_payload(decode=True).decode()
                break
        self.assertEqual(text, "the body")

    def test_no_attachments_by_default(self):
        msg = build_email_message("me@x", ["a@b.c"], "s", "b")
        atts = list_attachments(message_from_bytes(msg.as_bytes()))
        self.assertEqual(atts, [])

    def test_attachment_attached(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "data.bin"
            f.write_bytes(b"\x01\x02\x03payload")
            msg = build_email_message("me@x", ["a@b.c"], "s", "b", [str(f)])
            atts = list_attachments(message_from_bytes(msg.as_bytes()))
            self.assertEqual(len(atts), 1)
            name, content = atts[0]
            self.assertEqual(name, "data.bin")
            self.assertEqual(content, b"\x01\x02\x03payload")

    def test_multiple_attachments_preserve_order(self):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for n, body in enumerate([b"first", b"second", b"third"]):
                p = Path(d) / f"f{n}.bin"
                p.write_bytes(body)
                paths.append(str(p))
            msg = build_email_message("me@x", ["a@b.c"], "s", "b", paths)
            atts = list_attachments(message_from_bytes(msg.as_bytes()))
            self.assertEqual([n for n, _ in atts], ["f0.bin", "f1.bin", "f2.bin"])
            self.assertEqual([c for _, c in atts], [b"first", b"second", b"third"])

    def test_missing_attachment_raises_smexception(self):
        with self.assertRaises(SMException) as cm:
            build_email_message("me@x", ["a@b.c"], "s", "b", ["/no/such/file.bin"])
        self.assertIn("Error attaching file", str(cm.exception))


# ─── SMTP fake server + integration tests for send_email ─────────────────────────

def _generate_test_cert():
    """Generate a self-signed cert+key in a tempdir using the system openssl. Returns
    (cert_path, key_path, sha256_hex, tempdir) or None if openssl is unavailable."""
    tmp = tempfile.mkdtemp(prefix="sm-test-cert-")
    cert_path = Path(tmp) / "cert.pem"
    key_path = Path(tmp) / "key.pem"
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ],
            check=True, capture_output=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    cert_sha256 = hashlib.sha256(der).hexdigest()
    return cert_path, key_path, cert_sha256, tmp


class _FakeSMTPServer:
    """Threaded SMTP-with-STARTTLS server for testing. Captures the delivered message bytes
    in `self.delivered` and the envelope in `self.mail_from` / `self.rcpts`. Set `fail_auth=True`
    to simulate AUTH failure."""

    def __init__(self, cert_path, key_path, *, fail_auth=False):
        self.cert_path = str(cert_path)
        self.key_path = str(key_path)
        self.fail_auth = fail_auth
        self.delivered = None
        self.mail_from = None
        self.rcpts = []
        self.host = "127.0.0.1"
        self.port = None
        self._server = None
        self._thread = None

    def start(self):
        outer = self
        class Handler(socketserver.StreamRequestHandler):
            timeout = 5

            def _w(self, line):
                self.wfile.write(line.encode("ascii") + b"\r\n")
                self.wfile.flush()

            def handle(self):
                self._ssl_sock = None
                try:
                    self._handle()
                except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
                    pass  # client disconnected (e.g. after auth failure or pinning mismatch); not an error
                finally:
                    # When STARTTLS replaces self.connection, socketserver only knows about the original
                    # plain socket — the SSL-wrapped one leaks unless we close it ourselves.
                    if self._ssl_sock is not None:
                        try:
                            self._ssl_sock.close()
                        except (OSError, ssl.SSLError):
                            pass

            def _handle(self):
                self._w("220 fake.localhost SMTP")
                in_tls = False
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    line = raw.decode("ascii", "replace").rstrip("\r\n")
                    cmd = line.split(" ", 1)[0].upper() if line else ""
                    if cmd in ("HELO", "EHLO"):
                        # advertise STARTTLS + AUTH PLAIN
                        self._w("250-localhost")
                        self._w("250-AUTH PLAIN")
                        self._w("250 STARTTLS")
                    elif cmd == "STARTTLS" and not in_tls:
                        self._w("220 ready")
                        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        ctx.load_cert_chain(certfile=outer.cert_path, keyfile=outer.key_path)
                        self.connection = ctx.wrap_socket(self.connection, server_side=True)
                        self._ssl_sock = self.connection
                        self.rfile = self.connection.makefile("rb", -1)
                        self.wfile = self.connection.makefile("wb", 0)
                        in_tls = True
                    elif cmd == "AUTH":
                        if outer.fail_auth:
                            self._w("535 5.7.8 authentication failed")
                            continue
                        rest = line[5:].strip()
                        if rest.upper().startswith("PLAIN "):
                            self._w("235 2.7.0 authenticated")
                        elif rest.upper() == "PLAIN":
                            self._w("334 ")
                            self.rfile.readline()  # eat credentials
                            self._w("235 2.7.0 authenticated")
                        else:
                            self._w("504 5.5.4 mechanism not supported")
                    elif cmd == "MAIL":
                        outer.mail_from = line.split(":", 1)[1].strip().strip("<>")
                        self._w("250 ok")
                    elif cmd == "RCPT":
                        outer.rcpts.append(line.split(":", 1)[1].strip().strip("<>"))
                        self._w("250 ok")
                    elif cmd == "DATA":
                        self._w("354 end with <CRLF>.<CRLF>")
                        chunks = []
                        while True:
                            data_line = self.rfile.readline()
                            if data_line in (b".\r\n", b".\n"):
                                break
                            if data_line.startswith(b"."):  # SMTP dot-stuffing
                                data_line = data_line[1:]
                            chunks.append(data_line)
                        outer.delivered = b"".join(chunks)
                        self._w("250 ok")
                    elif cmd == "QUIT":
                        self._w("221 bye")
                        return
                    elif cmd == "RSET":
                        self._w("250 ok")
                    elif cmd == "NOOP":
                        self._w("250 ok")
                    else:
                        self._w(f"500 unknown: {line[:30]}")

        class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = _Server((self.host, 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)


class TestSendEmailIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cert_data = _generate_test_cert()
        if cert_data is None:
            raise unittest.SkipTest("openssl not available — skipping send_email integration tests")
        cls.cert_path, cls.key_path, cls.cert_sha256, cls._cert_tmpdir = cert_data

    def _make_account(self, port):
        return MailConnectionInfos(
            name="test",
            username="user@localhost",
            password="hunter2",
            smtp_ssl_host="localhost",  # must match cert CN
            smtp_ssl_port=port,
            pinned_smtp_certificate_sha256=self.cert_sha256,
            ssl_cafile=str(self.cert_path),  # trust our self-signed CA
        )

    def setUp(self):
        self.fake = _FakeSMTPServer(self.cert_path, self.key_path)
        self.fake.start()

    def tearDown(self):
        self.fake.stop()

    def test_basic_send(self):
        account = self._make_account(self.fake.port)
        send_email(account, ["recipient@example.com"], "Hello", "body text", Context())
        # Envelope captured
        self.assertEqual(self.fake.mail_from, "user@localhost")
        self.assertEqual(self.fake.rcpts, ["recipient@example.com"])
        # Message body captured + parses correctly
        self.assertIsNotNone(self.fake.delivered)
        delivered_msg = message_from_bytes(self.fake.delivered)
        self.assertEqual(delivered_msg["From"], "user@localhost")
        self.assertEqual(delivered_msg["To"], "recipient@example.com")
        self.assertEqual(delivered_msg["Subject"], "Hello")
        # Body inside the multipart
        body = next(p for p in delivered_msg.walk() if p.get_content_type() == "text/plain")
        self.assertEqual(body.get_payload(decode=True).decode().strip(), "body text")

    def test_send_with_attachment(self):
        with tempfile.TemporaryDirectory() as d:
            attachment = Path(d) / "report.bin"
            attachment.write_bytes(b"PAYLOAD\x00\xff")
            account = self._make_account(self.fake.port)
            send_email(account, ["a@b.c"], "subj", "msg", Context(), attachment_paths=[str(attachment)])

        delivered_msg = message_from_bytes(self.fake.delivered)
        atts = list_attachments(delivered_msg)
        self.assertEqual(len(atts), 1)
        name, content = atts[0]
        self.assertEqual(name, "report.bin")
        self.assertEqual(content, b"PAYLOAD\x00\xff")

    def test_send_multiple_recipients(self):
        account = self._make_account(self.fake.port)
        send_email(account, ["a@x", "b@y", "c@z"], "subj", "msg", Context())
        self.assertEqual(self.fake.rcpts, ["a@x", "b@y", "c@z"])

    def test_auth_failure_raises_smexception(self):
        self.fake.stop()  # restart with fail_auth
        self.fake = _FakeSMTPServer(self.cert_path, self.key_path, fail_auth=True)
        self.fake.start()
        account = self._make_account(self.fake.port)
        with self.assertRaises(SMException) as cm:
            send_email(account, ["a@b.c"], "s", "m", Context())
        self.assertIn("Auth error", str(cm.exception))

    def test_wrong_pinned_cert_rejected(self):
        # Pin a SHA256 that doesn't match — TLS handshake should fail before AUTH.
        account = self._make_account(self.fake.port)
        account.pinned_smtp_certificate_sha256 = "0" * 64
        with self.assertRaises(SMException):
            send_email(account, ["a@b.c"], "s", "m", Context())


if __name__ == "__main__":
    unittest.main()
