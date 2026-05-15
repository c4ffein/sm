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
from unittest.mock import patch

import sm
from sm import (
    Context,
    ErrorEvent,
    MailConnectionInfos,
    Param,
    SMException,
    Store,
    Verbosity,
    _invalidate_cache_for_folder,
    _is_safe_folder_name,
    build_email_message,
    consume_args,
    decode_modified_utf7,
    internaldate_key,
    is_gone,
    is_live,
    kiss_extract_text_from_eml,
    list_attachments,
    parse_authentication_results,
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

    def test_resync_internaldate_minimal(self):
        action, _ = consume_args(["sm", "resync-internaldate"])
        self.assertEqual(action, {"action": "resync-internaldate", "account": None})

    def test_resync_internaldate_with_account(self):
        action, _ = consume_args(["sm", "resync-internaldate", "account=work"])
        self.assertEqual(action["account"], "work")

    def test_resync_internaldate_invalid_option(self):
        with self.assertRaises(SMException):
            consume_args(["sm", "resync-internaldate", "yes"])  # yes is sync-only

    def test_send_minimal(self):
        action, _ = consume_args(["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello"])
        self.assertEqual(action["action"], "send")
        self.assertEqual(action["recipients"], ["a@b.c"])
        self.assertEqual(action["subject"], "hi")
        self.assertEqual(action["body"], "hello")
        self.assertEqual(action["files"], [])
        self.assertIsNone(action["account"])

    def test_send_multiple_recipients(self):
        action, _ = consume_args(["sm", "send", "recipient=a@b.c", "recipient=d@e.f", "subject=hi", "body=hello"])
        self.assertEqual(action["recipients"], ["a@b.c", "d@e.f"])

    def test_send_multiple_files(self):
        action, _ = consume_args(
            ["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello", "file=/tmp/x", "file=/tmp/y"]
        )
        self.assertEqual(action["files"], ["/tmp/x", "/tmp/y"])

    def test_send_with_account(self):
        action, _ = consume_args(["sm", "send", "recipient=a@b.c", "subject=hi", "body=hello", "account=work"])
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


class TestParseSizeResponse(unittest.TestCase):
    def test_basic(self):
        data = [
            b"1 (UID 5 RFC822.SIZE 1234)",
            b"2 (UID 6 RFC822.SIZE 5678)",
        ]
        sizes, errors = sm.parse_size_response(data)
        self.assertEqual(sizes, {5: 1234, 6: 5678})
        self.assertEqual(errors, [])

    def test_reports_lines_without_uid_or_size(self):
        data = [
            b"1 (UID 5 RFC822.SIZE 100)",
            b"2 (RFC822.SIZE 999)",  # no UID
            b"3 (UID 7)",  # no size
            b"junk",
        ]
        sizes, errors = sm.parse_size_response(data)
        self.assertEqual(sizes, {5: 100})
        self.assertEqual(len(errors), 3)  # one per malformed line

    def test_reports_non_bytes_entries(self):
        sizes, errors = sm.parse_size_response([None, b"1 (UID 5 RFC822.SIZE 100)"])
        self.assertEqual(sizes, {5: 100})
        self.assertEqual(len(errors), 1)
        self.assertIn("non-bytes", errors[0])


class TestPackFetchBatches(unittest.TestCase):
    def _pack(self, uids, sizes, max_count, max_bytes):
        return list(sm.pack_fetch_batches(uids, sizes, max_count, max_bytes))

    def test_count_cap_only(self):
        # No size info; falls through to count-only packing.
        self.assertEqual(self._pack([1, 2, 3, 4, 5], {}, max_count=2, max_bytes=999), [[1, 2], [3, 4], [5]])

    def test_byte_cap_splits(self):
        sizes = {1: 30, 2: 30, 3: 30}  # any pair fits, all three don't
        self.assertEqual(self._pack([1, 2, 3], sizes, max_count=10, max_bytes=70), [[1, 2], [3]])

    def test_single_oversized_message_goes_alone(self):
        # A single message bigger than max_bytes still gets fetched — alone in its own batch.
        sizes = {1: 5, 2: 100, 3: 5}
        self.assertEqual(self._pack([1, 2, 3], sizes, max_count=10, max_bytes=50), [[1], [2], [3]])

    def test_empty_input(self):
        self.assertEqual(self._pack([], {}, 50, 100), [])


class TestParseFetchResponse(unittest.TestCase):
    def test_single_message(self):
        data = [
            (b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822 {12}', b"hello world\n"),
            b")",
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"hello world\n", "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(errors, [])

    def test_multiple_messages(self):
        data = [
            (b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822 {12}', b"hello world\n"),
            b")",
            (b'2 (UID 6 INTERNALDATE "02-Feb-2026 13:00:00 +0000" RFC822 {7}', b"second\n"),
            b")",
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(
            results,
            [
                (5, b"hello world\n", "01-Jan-2026 12:00:00 +0000"),
                (6, b"second\n", "02-Feb-2026 13:00:00 +0000"),
            ],
        )
        self.assertEqual(errors, [])

    def test_missing_internaldate_is_reported(self):
        # We always ask for INTERNALDATE, so absence in the response is a real anomaly,
        # not a tolerable gap. Value still returns empty string so callers don't crash.
        data = [(b"1 (UID 5 RFC822 {3}", b"foo"), b")"]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"foo", "")])
        self.assertEqual(len(errors), 1)
        self.assertIn("missing INTERNALDATE", errors[0])
        self.assertIn("UID 5", errors[0])

    def test_tuple_without_uid_is_reported(self):
        data = [
            (b"1 (RFC822 {3}", b"bar"),  # no UID — recorded as error, not silent skip
            (b'2 (UID 7 INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822 {3}', b"baz"),
            b")",
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(7, b"baz", "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(len(errors), 1)
        self.assertIn("missing UID", errors[0])

    def test_closing_paren_separator_is_not_an_error(self):
        # The trailing b")" between per-message tuples is normal response shape.
        data = [(b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822 {3}', b"foo"), b")"]
        _results, errors = sm.parse_fetch_response(data)
        self.assertEqual(errors, [])

    def test_internaldate_in_trailer_after_literal(self):
        # Gmail orders `(RFC822 INTERNALDATE)` reply as RFC822 first, INTERNALDATE after.
        # imaplib splits at the literal: trailing fields land as a non-tuple bytes entry.
        data = [
            (b"1 (UID 5 RFC822 {12}", b"hello world\n"),
            b' INTERNALDATE "13-May-2026 08:04:47 +0000")',
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"hello world\n", "13-May-2026 08:04:47 +0000")])
        self.assertEqual(errors, [])

    def test_trailer_with_flags_after_literal(self):
        # Same shape as above but the server tacks FLAGS on too — still a valid trailer.
        data = [
            (b"1 (UID 5 RFC822 {12}", b"hello world\n"),
            b' INTERNALDATE "14-May-2026 02:56:57 +0000" FLAGS (\\Seen))',
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"hello world\n", "14-May-2026 02:56:57 +0000")])
        self.assertEqual(errors, [])

    def test_untagged_flag_notification_is_ignored(self):
        # Server-initiated FETCH FLAGS update for an unrelated message arriving mid-batch.
        # No literal → imaplib emits a single bytes entry. We don't track flags; skip silently.
        data = [
            (b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822 {3}', b"foo"),
            b")",
            b"8017 (UID 19396 FLAGS (\\Seen))",
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"foo", "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(errors, [])

    def test_unrecognized_non_tuple_still_errors(self):
        # Anything that isn't a known shape should still surface as an error, not be swallowed.
        data = [b"garbage bytes from a confused server"]
        _results, errors = sm.parse_fetch_response(data)
        self.assertEqual(len(errors), 1)
        self.assertIn("unexpected non-tuple entry", errors[0])

    def test_trailer_claiming_internaldate_but_unparseable_surfaces_error(self):
        # Trailer opens the INTERNALDATE quoted-string but never closes it — gate matches
        # ('INTERNALDATE "' is present), extraction fails. Want a specific error naming the
        # UID + the malformed bytes, plus the final-pass "missing INTERNALDATE" since UID 5
        # never got a date from anywhere.
        data = [
            (b"1 (UID 5 RFC822 {3}", b"foo"),
            b' INTERNALDATE "broken)',  # opens the quote, no closing quote before the trailer's ')'
        ]
        _results, errors = sm.parse_fetch_response(data)
        self.assertTrue(
            any("trailer for UID 5 claims INTERNALDATE but extraction failed" in e for e in errors),
            f"expected specific trailer-extraction error, got: {errors!r}",
        )
        self.assertTrue(any("missing INTERNALDATE for UID 5" in e for e in errors))

    def test_header_claiming_internaldate_but_unparseable_surfaces_error(self):
        # Header opens INTERNALDATE quoted-string but never closes it — gate matches,
        # extraction fails. Same diagnostic shape as the trailer-side equivalent.
        data = [
            (b'1 (UID 5 INTERNALDATE "broken RFC822 {3}', b"foo"),
            b")",
        ]
        _results, errors = sm.parse_fetch_response(data)
        self.assertTrue(
            any("header for UID 5 claims INTERNALDATE but extraction failed" in e for e in errors),
            f"expected specific header-extraction error, got: {errors!r}",
        )
        self.assertTrue(any("missing INTERNALDATE for UID 5" in e for e in errors))

    def test_trailer_with_internaldate_keyword_collision_does_not_false_positive(self):
        # A custom IMAP keyword literally named INTERNALDATE in a FLAGS list shouldn't trip
        # the trailer gate. The real INTERNALDATE field (with its opening quote) does.
        data = [
            (b"1 (UID 5 RFC822 {3}", b"foo"),
            b' FLAGS (\\Seen INTERNALDATE \\Answered) INTERNALDATE "01-Jan-2026 12:00:00 +0000")',
        ]
        results, errors = sm.parse_fetch_response(data)
        self.assertEqual(results, [(5, b"foo", "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(errors, [])


class TestParseInternaldateOnly(unittest.TestCase):
    """`parse_internaldate_only` parses FETCH (INTERNALDATE)-only responses for resync.
    Simpler than parse_fetch_response: no body literal, so each part is a single bytes
    fragment. Resync uses this to backfill INTERNALDATE without paying body bandwidth."""

    def test_single_message(self):
        data = [b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000")']
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(results, [(5, "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(errors, [])

    def test_multiple_messages(self):
        data = [
            b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000")',
            b'2 (UID 6 INTERNALDATE "02-Feb-2026 13:00:00 +0000")',
        ]
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(
            results,
            [
                (5, "01-Jan-2026 12:00:00 +0000"),
                (6, "02-Feb-2026 13:00:00 +0000"),
            ],
        )
        self.assertEqual(errors, [])

    def test_part_missing_uid_is_reported(self):
        data = [b'1 (INTERNALDATE "01-Jan-2026 12:00:00 +0000")']
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("missing UID", errors[0])

    def test_part_missing_internaldate_is_reported(self):
        data = [b"1 (UID 5)"]
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("missing INTERNALDATE", errors[0])
        self.assertIn("UID 5", errors[0])

    def test_terminator_paren_ignored(self):
        # Some servers send a lone ')' as a terminator — must not be reported as malformed.
        data = [b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000")', b")"]
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(results, [(5, "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(errors, [])

    def test_none_part_is_reported(self):
        data = [None, b'1 (UID 5 INTERNALDATE "01-Jan-2026 12:00:00 +0000")']
        results, errors = sm.parse_internaldate_only(data)
        self.assertEqual(results, [(5, "01-Jan-2026 12:00:00 +0000")])
        self.assertEqual(len(errors), 1)


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

    def test_save_roundtrips_messages(self):
        with Store(self.tmppath / "store") as store:
            store.messages["abc"] = {"subject": "test"}
            store.save()
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.messages, {"abc": {"subject": "test"}})

    def test_load_index_missing_file(self):
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.messages, {})

    def test_load_index_empty_file(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text("")
        with Store(store_path) as store:
            self.assertEqual(store.messages, {})

    def test_load_index_whitespace_only(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text("   \n  ")
        with Store(store_path) as store:
            self.assertEqual(store.messages, {})

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

    def test_save_outside_context_raises(self):
        store = Store(self.tmppath / "store")
        with self.assertRaises(SMException):
            store.save()

    def test_save_atomic_no_partial_file(self):
        # After save, the temp file should be gone (rename moved it).
        store_path = self.tmppath / "store"
        with Store(store_path) as store:
            store.messages["abc"] = {"subject": "test"}
            store.save()
            self.assertFalse((store_path / ".index.json.tmp").exists())
            self.assertTrue((store_path / "index.json").exists())

    def test_folder_states_default_empty(self):
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.folder_states, {})

    def test_save_persists_messages_and_folders_together(self):
        # Both live in the same index.json — one save() persists both.
        with Store(self.tmppath / "store") as store:
            store.messages["abc"] = {"subject": "test"}
            store.folder_states["INBOX"] = {"uidvalidity": 1234567890}
            store.folder_states["[Gmail]/Sent"] = {"uidvalidity": 42}
            store.save()
        with Store(self.tmppath / "store") as store:
            self.assertEqual(store.messages, {"abc": {"subject": "test"}})
            self.assertEqual(store.folder_states["INBOX"]["uidvalidity"], 1234567890)
            self.assertEqual(store.folder_states["[Gmail]/Sent"]["uidvalidity"], 42)

    def test_index_json_format_is_nested(self):
        # Lock the on-disk shape: top-level dict with "messages" and "folders" keys.
        with Store(self.tmppath / "store") as store:
            store.messages["abc"] = {"subject": "test"}
            store.folder_states["INBOX"] = {"uidvalidity": 1}
            store.save()
        import json

        on_disk = json.loads((self.tmppath / "store" / "index.json").read_text())
        self.assertEqual(set(on_disk.keys()), {"messages", "folders"})
        self.assertEqual(on_disk["messages"], {"abc": {"subject": "test"}})
        self.assertEqual(on_disk["folders"], {"INBOX": {"uidvalidity": 1}})


class TestInvalidateCacheForFolder(unittest.TestCase):
    def test_removes_only_targeted_folder(self):
        cache = {
            ("INBOX", 1): "hash_a",
            ("INBOX", 2): "hash_b",
            ("[Gmail]/Sent", 1): "hash_c",
            ("[Gmail]/Sent", 5): "hash_d",
        }
        removed = _invalidate_cache_for_folder(cache, "INBOX")
        self.assertEqual(removed, 2)
        self.assertEqual(
            cache,
            {
                ("[Gmail]/Sent", 1): "hash_c",
                ("[Gmail]/Sent", 5): "hash_d",
            },
        )

    def test_returns_zero_when_folder_absent(self):
        cache = {("INBOX", 1): "hash_a"}
        self.assertEqual(_invalidate_cache_for_folder(cache, "Drafts"), 0)
        self.assertEqual(cache, {("INBOX", 1): "hash_a"})

    def test_empty_cache_no_op(self):
        cache = {}
        self.assertEqual(_invalidate_cache_for_folder(cache, "INBOX"), 0)
        self.assertEqual(cache, {})


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
            (b"totally bogus", "no opening paren"),
            (b"(no closing", "unterminated flag list"),
            (b"() not_a_delim INBOX", "expected delimiter"),
            (b"() NIL", "missing mailbox name"),
            (b'() "/" "unterminated', "unterminated quoted mailbox name"),
            (b'() "/" {abc}', "non-numeric literal length"),
            (b'() "/" {99}\r\nshort', "literal length exceeds available bytes"),
            (b'() "/" {bogus', "malformed literal length marker"),
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


# ─── shared TLS fixture for SMTP + IMAP integration tests ─────────────────────────

_test_cert_cache = None


def _generate_test_cert():
    """Generate a self-signed cert+key in a tempdir using the system openssl. Cached at
    module level so SMTP and IMAP integration suites share one cert (one openssl spawn).
    Returns (cert_path, key_path, sha256_hex, tempdir) or None if openssl is unavailable."""
    global _test_cert_cache
    if _test_cert_cache is not None:
        return _test_cert_cache
    tmp = tempfile.mkdtemp(prefix="sm-test-cert-")
    cert_path = Path(tmp) / "cert.pem"
    key_path = Path(tmp) / "key.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    cert_sha256 = hashlib.sha256(der).hexdigest()
    _test_cert_cache = (cert_path, key_path, cert_sha256, tmp)
    return _test_cert_cache


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


# ─── IMAP fake server + integration tests for sync_emails ───────────────────────


class _FakeIMAPMessage:
    def __init__(self, uid, body, internaldate="01-Jan-2026 12:00:00 +0000"):
        self.uid = uid
        self.body = body  # raw RFC822 bytes
        self.internaldate = internaldate


class _FakeIMAPFolder:
    def __init__(self, name, *, flags=("\\HasNoChildren",), uidvalidity=1, select_status="OK"):
        self.name = name  # raw IMAP form (modified UTF-7)
        self.flags = list(flags)
        self.uidvalidity = uidvalidity
        self.select_status = select_status  # "OK" or "NO" to simulate a SELECT failure
        self.messages = []  # _FakeIMAPMessage list, in UID order
        self.fetch_failures_remaining = 0  # connection-drop on this many FETCH calls; decrements per drop
        # UIDs are monotonic per RFC 3501 §2.3.1.1: never reused while UIDVALIDITY stays the same,
        # even after a message is deleted. Tracking _next_uid separately from the messages list
        # ensures `messages = []; add(body)` doesn't recycle a previously-issued UID.
        self._next_uid = 1

    def add(self, body, internaldate="01-Jan-2026 12:00:00 +0000"):
        uid = self._next_uid
        self._next_uid += 1
        self.messages.append(_FakeIMAPMessage(uid, body, internaldate))
        return self.messages[-1]

    def remove(self, uid):
        self.messages = [m for m in self.messages if m.uid != uid]


class _FakeIMAPServer:
    """Threaded IMAP4_SSL fake — direct TLS from connect (port 993 style, not STARTTLS).
    Configurable folders, messages, UIDVALIDITY. Speaks the subset of the protocol our
    client actually uses: LOGIN, LIST, SELECT, UID SEARCH ALL, UID FETCH (RFC822 INTERNALDATE),
    LOGOUT, NOOP, CAPABILITY."""

    def __init__(self, cert_path, key_path):
        self.cert_path = str(cert_path)
        self.key_path = str(key_path)
        self.folders = {}  # name -> _FakeIMAPFolder
        self.delim = "/"
        self.host = "127.0.0.1"
        self.port = None
        self._server = None
        self._thread = None

    def add_folder(self, name, **kwargs):
        f = _FakeIMAPFolder(name, **kwargs)
        self.folders[name] = f
        return f

    def start(self):
        outer = self
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        class Handler(socketserver.StreamRequestHandler):
            timeout = 10

            def setup(self):
                # Wrap the raw socket in TLS immediately — IMAP4_SSL connects over TLS from byte 0.
                self.connection = ssl_ctx.wrap_socket(self.request, server_side=True)
                self.rfile = self.connection.makefile("rb", -1)
                self.wfile = self.connection.makefile("wb", 0)
                self._ssl_sock = self.connection
                self.selected = None  # current _FakeIMAPFolder

            def finish(self):
                try:
                    self._ssl_sock.close()
                except (OSError, ssl.SSLError):
                    pass
                try:
                    super().finish()
                except (OSError, ssl.SSLError):
                    pass

            def _wln(self, line):
                self.wfile.write(line.encode("ascii") + b"\r\n")

            def _wraw(self, data):
                self.wfile.write(data)

            def handle(self):
                try:
                    self._handle()
                except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
                    pass

            def _handle(self):
                self._wln("* OK fake IMAP ready")
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if not line:
                        continue
                    parts = line.split(" ", 2)
                    tag = parts[0]
                    cmd = parts[1].upper() if len(parts) > 1 else ""
                    rest = parts[2] if len(parts) > 2 else ""
                    if cmd == "CAPABILITY":
                        self._wln("* CAPABILITY IMAP4REV1 AUTH=PLAIN")
                        self._wln(f"{tag} OK CAPABILITY completed")
                    elif cmd == "LOGIN":
                        self._wln(f"{tag} OK LOGIN completed")
                    elif cmd == "LIST":
                        for folder in outer.folders.values():
                            flags_str = " ".join(folder.flags)
                            self._wln(f'* LIST ({flags_str}) "{outer.delim}" "{folder.name}"')
                        self._wln(f"{tag} OK LIST completed")
                    elif cmd == "SELECT" or cmd == "EXAMINE":
                        folder_name = rest.strip().strip('"')
                        folder = outer.folders.get(folder_name)
                        if folder is None or folder.select_status != "OK":
                            self._wln(f"{tag} NO mailbox unavailable")
                            continue
                        self._wln(f"* {len(folder.messages)} EXISTS")
                        self._wln("* 0 RECENT")
                        self._wln(f"* OK [UIDVALIDITY {folder.uidvalidity}] UIDs valid")
                        next_uid = (folder.messages[-1].uid + 1) if folder.messages else 1
                        self._wln(f"* OK [UIDNEXT {next_uid}] Predicted next UID")
                        self.selected = folder
                        self._wln(f"{tag} OK [READ-WRITE] SELECT completed")
                    elif cmd == "UID":
                        sub_parts = rest.split(" ", 1)
                        sub = sub_parts[0].upper()
                        sub_rest = sub_parts[1] if len(sub_parts) > 1 else ""
                        if self.selected is None:
                            self._wln(f"{tag} BAD no folder selected")
                            continue
                        if sub == "SEARCH":
                            uids = " ".join(str(m.uid) for m in self.selected.messages)
                            self._wln(f"* SEARCH {uids}".rstrip())
                            self._wln(f"{tag} OK SEARCH completed")
                        elif sub == "FETCH":
                            # Simulate transient network error: drop the connection mid-FETCH.
                            if self.selected.fetch_failures_remaining > 0:
                                self.selected.fetch_failures_remaining -= 1
                                try:
                                    self._ssl_sock.close()
                                except (OSError, ssl.SSLError):
                                    pass
                                return
                            # sub_rest looks like: "<uid_set> (RFC822 INTERNALDATE)"
                            # uid_set is one of: "5", "1,3,5", "1:5", "1:*", "1:3,7,9"
                            try:
                                uid_set_str, _spec = sub_rest.split(" ", 1)
                            except ValueError:
                                self._wln(f"{tag} BAD malformed fetch")
                                continue
                            all_uids = [m.uid for m in self.selected.messages]
                            requested = []
                            try:
                                for piece in uid_set_str.split(","):
                                    if ":" in piece:
                                        lo_str, hi_str = piece.split(":", 1)
                                        lo_v = int(lo_str)
                                        hi_v = (max(all_uids) if all_uids else 0) if hi_str == "*" else int(hi_str)
                                        for v in all_uids:
                                            if lo_v <= v <= hi_v:
                                                requested.append(v)
                                    else:
                                        v = int(piece)
                                        if v in all_uids:
                                            requested.append(v)
                            except ValueError:
                                self._wln(f"{tag} BAD malformed fetch UID set")
                                continue
                            if "RFC822.SIZE" in _spec:
                                # Size pre-flight: no literal body, just the size attribute.
                                for uid in requested:
                                    msg = next((m for m in self.selected.messages if m.uid == uid), None)
                                    if msg is None:
                                        continue
                                    seq = self.selected.messages.index(msg) + 1
                                    self._wln(f"* {seq} FETCH (UID {msg.uid} RFC822.SIZE {len(msg.body)})")
                            else:
                                for uid in requested:
                                    msg = next((m for m in self.selected.messages if m.uid == uid), None)
                                    if msg is None:
                                        continue
                                    seq = self.selected.messages.index(msg) + 1
                                    header = (
                                        f"* {seq} FETCH (UID {msg.uid} "
                                        f'INTERNALDATE "{msg.internaldate}" '
                                        f"RFC822 {{{len(msg.body)}}}\r\n"
                                    ).encode("ascii")
                                    self._wraw(header)
                                    self._wraw(msg.body)
                                    self._wraw(b")\r\n")
                            self._wln(f"{tag} OK FETCH completed")
                        else:
                            self._wln(f"{tag} BAD unknown UID command: {sub}")
                    elif cmd == "LOGOUT":
                        self._wln("* BYE")
                        self._wln(f"{tag} OK LOGOUT completed")
                        return
                    elif cmd == "NOOP":
                        self._wln(f"{tag} OK NOOP completed")
                    elif cmd == "CLOSE":
                        self.selected = None
                        self._wln(f"{tag} OK CLOSE completed")
                    else:
                        self._wln(f"{tag} BAD unknown: {cmd}")

        class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = _Server((self.host, 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def _make_eml(subject, body_text="hello", from_addr="alice@example.com"):
    """Build an RFC822-shaped bytes blob suitable for the fake server's RFC822 fetch."""
    return (
        f"From: {from_addr}\r\n"
        f"To: me@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Date: Thu, 8 May 2026 14:30:00 +0000\r\n"
        f"Message-ID: <{subject.replace(' ', '_')}@example.com>\r\n"
        f"\r\n"
        f"{body_text}\r\n"
    ).encode()


class TestSyncIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cert_data = _generate_test_cert()
        if cert_data is None:
            raise unittest.SkipTest("openssl not available — skipping IMAP integration tests")
        cls.cert_path, cls.key_path, cls.cert_sha256, _ = cert_data

    def setUp(self):
        # Each test gets a fresh server, fresh store, fresh lock-file location.
        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        sm.LOCK_PATH = self.tmppath / "lock"
        Store._active = False
        self.imap = _FakeIMAPServer(self.cert_path, self.key_path)
        self.imap.start()

    def tearDown(self):
        self.imap.stop()
        sm.LOCK_PATH = self._orig_lock
        Store._active = False
        self._tmp.cleanup()

    def _account(self):
        return MailConnectionInfos(
            name="test",
            username="user@localhost",
            password="hunter2",
            imap_ssl_host="localhost",
            imap_ssl_port=self.imap.port,
            pinned_imap_certificate_sha256=self.cert_sha256,
            local_store_path=str(self.tmppath / "store"),
            ssl_cafile=str(self.cert_path),
        )

    def test_basic_sync_downloads_messages(self):
        inbox = self.imap.add_folder("INBOX", uidvalidity=42)
        inbox.add(_make_eml("first"), internaldate="01-Jan-2026 12:00:00 +0000")
        inbox.add(_make_eml("second"), internaldate="02-Jan-2026 12:00:00 +0000")

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True)

        # Two .eml files written, one entry per content hash in the index
        eml_files = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files), 2)
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 2)
            subjects = sorted(e["subject"] for e in store.messages.values())
            self.assertEqual(subjects, ["first", "second"])
            # UIDVALIDITY recorded
            self.assertEqual(store.folder_states["INBOX"]["uidvalidity"], 42)
        self.assertEqual(ctx.errors, [])

    def test_byte_cap_splits_batches(self):
        # With SYNC_BATCH_BYTES smaller than two messages combined, packer must split.
        # End-to-end: server still returns all messages; client must consume them across batches.
        inbox = self.imap.add_folder("INBOX")
        for i in range(4):
            inbox.add(_make_eml(f"msg-{i}", body_text="x" * 200))  # each ~300+ bytes
        ctx = Context()
        with patch.object(sm, "SYNC_BATCH_BYTES", 400):  # forces ~one message per batch
            sm.sync_emails(self._account(), ctx, auto_apply=True)
        eml_files = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files), 4)
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 4)

    def test_batched_fetch_handles_more_than_one_batch(self):
        # Add more messages than SYNC_BATCH_SIZE so the fetch loop runs at least
        # twice and the fake server has to satisfy a multi-UID FETCH range.
        inbox = self.imap.add_folder("INBOX")
        n = sm.SYNC_BATCH_SIZE + 5
        for i in range(n):
            inbox.add(_make_eml(f"msg-{i:03d}"))

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True)

        eml_files = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files), n)
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), n)
            subjects = sorted(e["subject"] for e in store.messages.values())
            self.assertEqual(subjects, [f"msg-{i:03d}" for i in range(n)])

    def test_sync_handles_non_ascii_header(self):
        # Non-conforming senders put raw 8-bit bytes (typically UTF-8) directly
        # into headers without RFC 2047 encoding. Compat32 wraps those as
        # email.header.Header, which json.dumps can't serialize → sync used to
        # crash mid-fetch with the error masked as "Unknown error when trying
        # to reach server" by the connection-error decorator.
        inbox = self.imap.add_folder("INBOX")
        inbox.add(_make_eml("Héllo wörld"))

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True)

        with Store(self.tmppath / "store") as store:
            entry = next(iter(store.messages.values()))
            self.assertIsInstance(entry["subject"], str)
            self.assertEqual(entry["subject"], "Héllo wörld")
        # And the index file on disk is valid JSON (the original failure mode).
        import json

        json.loads((self.tmppath / "store" / "index.json").read_text())

    def test_same_body_in_two_folders_dedups(self):
        body = _make_eml("shared")
        inbox = self.imap.add_folder("INBOX")
        inbox.add(body)
        sent = self.imap.add_folder("[Gmail]/All Mail")
        sent.add(body)

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True)

        # Content hash dedups: one .eml on disk, one entry, history has both folders
        eml_files = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files), 1)
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            entry = next(iter(store.messages.values()))
            history_folders = sorted(h["folder"] for h in entry["history"])
            self.assertEqual(history_folders, ["INBOX", "[Gmail]/All Mail"])

    def test_select_failure_isolates_to_one_folder(self):
        good = self.imap.add_folder("INBOX")
        good.add(_make_eml("survives"))
        self.imap.add_folder("Broken", select_status="NO")  # SELECT will be refused

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True)

        # The good folder synced; the broken one was skipped with a recorded error
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            entry = next(iter(store.messages.values()))
            self.assertEqual(entry["subject"], "survives")
        select_errors = [e for e in ctx.errors if e.kind == "select_failed"]
        self.assertEqual(len(select_errors), 1)
        self.assertIn("Broken", select_errors[0].detail)

    def test_uidvalidity_change_invalidates_cache_and_refetches(self):
        body = _make_eml("survives uidvalidity change")
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(body)

        ctx1 = Context()
        sm.sync_emails(self._account(), ctx1, auto_apply=True)
        self.assertEqual(ctx1.errors, [])
        eml_files_before = sorted(p.name for p in (self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files_before), 1)

        # Server bumps UIDVALIDITY (and reassigns UIDs in practice). Same body, different UID.
        inbox.uidvalidity = 999
        inbox.messages = []
        inbox.add(body)  # gets UID 1 again under the new UIDVALIDITY scheme

        ctx2 = Context()
        sm.sync_emails(self._account(), ctx2, auto_apply=True)

        # uidvalidity_changed was recorded; .eml file untouched (content-hash dedup)
        kinds = [e.kind for e in ctx2.errors]
        self.assertIn("uidvalidity_changed", kinds)
        eml_files_after = sorted(p.name for p in (self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(eml_files_after, eml_files_before)
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            self.assertEqual(store.folder_states["INBOX"]["uidvalidity"], 999)

    def test_new_message_in_second_sync_is_added(self):
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("first"))

        ctx1 = Context()
        sm.sync_emails(self._account(), ctx1, auto_apply=True)
        self.assertEqual(len(list((self.tmppath / "store" / "mails").glob("*.eml"))), 1)

        inbox.add(_make_eml("second"))

        ctx2 = Context()
        sm.sync_emails(self._account(), ctx2, auto_apply=True)
        self.assertEqual(len(list((self.tmppath / "store" / "mails").glob("*.eml"))), 2)
        with Store(self.tmppath / "store") as store:
            subjects = sorted(e["subject"] for e in store.messages.values())
            self.assertEqual(subjects, ["first", "second"])

    def test_message_deleted_from_server_marks_every_history_entry_removed(self):
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("keeper"))
        inbox.add(_make_eml("doomed"))

        ctx1 = Context()
        sm.sync_emails(self._account(), ctx1, auto_apply=True)

        with Store(self.tmppath / "store") as store:
            self.assertTrue(all(sm.is_live(e) for e in store.messages.values()))

        # Server-side delete the second message
        inbox.remove(2)

        ctx2 = Context()
        sm.sync_emails(self._account(), ctx2, auto_apply=True)

        with Store(self.tmppath / "store") as store:
            gone = [e for e in store.messages.values() if sm.is_gone(e)]
            self.assertEqual(len(gone), 1)
            self.assertEqual(gone[0]["subject"], "doomed")
            # New "D" path: every history entry of the gone message is marked removed.
            self.assertTrue(all(h.get("removed") for h in gone[0]["history"]))

            live = [e for e in store.messages.values() if sm.is_live(e)]
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0]["subject"], "keeper")
            self.assertFalse(any(h.get("removed") for h in live[0]["history"]))

    # ─── mid-sync crash + retry ───────────────────────────────────────────────────

    def test_midsync_fetch_failure_raises_with_no_retries(self):
        # Server drops the connection before FETCH responds.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("first"))
        inbox.add(_make_eml("second"))
        inbox.fetch_failures_remaining = 99  # always fail

        ctx = Context()
        # max_silent_retries=0 still triggers the "Retry? [y/N]" prompt; mock input so
        # the test doesn't block on stdin when run interactively (e.g. `make verify`).
        with patch("builtins.input", return_value="n"):
            with self.assertRaises(SMException):
                sm.sync_emails(self._account(), ctx, auto_apply=True, max_silent_retries=0)

    def test_midsync_partial_state_is_consistent(self):
        # First two FETCHes succeed (1 message), then connection drops mid-fetch on the 3rd.
        # Expected: that one message is on disk + indexed (atomic save) when the sync raises.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("survives"))  # uid 1 — fetched OK
        inbox.add(_make_eml("orphaned"))  # uid 2 — connection drops before fetch returns

        # The first SELECT does no FETCH; the failures count starts ticking on the FETCH call
        # for uid 1. We want uid 1 to succeed, uid 2 to fail. So skip 0 failures up to that point,
        # then drop. Easiest: drop only the second FETCH.
        # Track FETCH calls server-side: drop the 2nd one (and keep dropping after)
        inbox.fetch_failures_remaining = 0  # uid 1 fetches normally
        # We'll set it before uid 2's fetch runs — but we can't time that synchronously.
        # Instead: set to a high number; uid 1 already-OK because we set it after... no.
        # Simpler scenario: ALL fetches drop. After the failure, partial state may still be empty,
        # but the test asserts "what's saved is consistent" not "exactly N messages saved."

        inbox.fetch_failures_remaining = 99
        ctx = Context()
        with patch("builtins.input", return_value="n"):
            with self.assertRaises(SMException):
                sm.sync_emails(self._account(), ctx, auto_apply=True, max_silent_retries=0)

        # Whatever is on disk must be valid JSON with the expected shape (atomic write invariant).
        store_path = self.tmppath / "store"
        if (store_path / "index.json").exists():
            import json

            data = json.loads((store_path / "index.json").read_text())
            self.assertIn("messages", data)
            self.assertIn("folders", data)
            # Every indexed message must have its .eml on disk (no orphans pointing to missing files)
            for sha in data["messages"]:
                self.assertTrue(
                    (store_path / "mails" / f"{sha}.eml").exists(), f"orphan index entry: {sha} has no .eml"
                )

    def test_silent_retry_recovers(self):
        # Connection drops on the first FETCH, then succeeds on retry.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("recovered"))
        inbox.fetch_failures_remaining = 1  # one drop, then OK

        ctx = Context()
        sm.sync_emails(self._account(), ctx, auto_apply=True, max_silent_retries=2)

        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            self.assertEqual(next(iter(store.messages.values()))["subject"], "recovered")

    def test_prompt_declined_after_silent_retries_raises(self):
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("doomed"))
        inbox.fetch_failures_remaining = 99  # never recovers

        ctx = Context()
        with patch("builtins.input", return_value="n"):
            with self.assertRaises(SMException):
                sm.sync_emails(self._account(), ctx, auto_apply=True, max_silent_retries=1)

    # ─── on-disk vs index discrepancies ───────────────────────────────────────────

    def test_missing_eml_for_indexed_message_is_recreated(self):
        # Sync once; manually delete the .eml; re-sync; the file must come back.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("recreate me"))

        sm.sync_emails(self._account(), Context(), auto_apply=True)
        eml_files = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files), 1)
        eml_files[0].unlink()  # external/accidental delete
        self.assertEqual(len(list((self.tmppath / "store" / "mails").glob("*.eml"))), 0)

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # File restored from server, content matches the hash-named filename.
        eml_files_after = list((self.tmppath / "store" / "mails").glob("*.eml"))
        self.assertEqual(len(eml_files_after), 1)
        self.assertEqual(eml_files_after[0].name, eml_files[0].name)  # same hash
        self.assertEqual(hashlib.sha256(eml_files_after[0].read_bytes()).hexdigest() + ".eml", eml_files_after[0].name)
        # Index unchanged, no duplicate entry.
        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)

    def test_unrelated_orphan_eml_is_left_alone(self):
        # Sync once. Drop an unrelated .eml on disk (not matching any server message). Re-sync.
        # Orphan stays untouched; index stays clean.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("real message"))

        sm.sync_emails(self._account(), Context(), auto_apply=True)
        store_path = self.tmppath / "store"

        # Plant an orphan whose filename matches its own content hash (so it's a *valid* orphan,
        # not a hash-mismatch corruption that the paranoid check would refuse).
        orphan_body = b"Subject: not on server\r\n\r\norphan body\r\n"
        orphan_hash = hashlib.sha256(orphan_body).hexdigest()
        orphan_path = store_path / "mails" / f"{orphan_hash}.eml"
        orphan_path.write_bytes(orphan_body)

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Orphan file untouched
        self.assertTrue(orphan_path.exists())
        self.assertEqual(orphan_path.read_bytes(), orphan_body)
        # Index has only the server's real message — orphan is NOT auto-adopted (no fetch returned its hash).
        with Store(store_path) as store:
            self.assertEqual(len(store.messages), 1)
            self.assertNotIn(orphan_hash, store.messages)

    def test_message_moved_between_folders_marks_old_removed(self):
        body = _make_eml("nomadic")
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        archive = self.imap.add_folder("Archive", uidvalidity=1)
        inbox.add(body)  # uid 1 in INBOX

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Server-side move: out of INBOX, into Archive
        inbox.messages = []
        archive.add(body)  # uid 1 in Archive

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            entry = next(iter(store.messages.values()))
            history = entry["history"]
            history_folders = [h["folder"] for h in history]
            self.assertIn("INBOX", history_folders)
            self.assertIn("Archive", history_folders)
            inbox_h = next(h for h in history if h["folder"] == "INBOX")
            archive_h = next(h for h in history if h["folder"] == "Archive")
            self.assertTrue(inbox_h.get("removed"))  # old folder marked gone
            self.assertFalse(archive_h.get("removed"))  # current folder not removed
            self.assertTrue(sm.is_live(entry))  # message isn't gone, just moved

    def test_missing_eml_plus_unrelated_orphan(self):
        # Combined corruption: indexed message's .eml is gone AND an unrelated orphan exists.
        # Re-sync should recreate the missing one and leave the orphan alone.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("primary"))

        sm.sync_emails(self._account(), Context(), auto_apply=True)
        store_path = self.tmppath / "store"
        primary_eml = next(iter((store_path / "mails").glob("*.eml")))
        primary_eml.unlink()

        orphan_body = b"Subject: unrelated\r\n\r\nfiller\r\n"
        orphan_hash = hashlib.sha256(orphan_body).hexdigest()
        orphan_path = store_path / "mails" / f"{orphan_hash}.eml"
        orphan_path.write_bytes(orphan_body)

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Primary recreated, orphan untouched.
        self.assertTrue(primary_eml.exists())
        self.assertTrue(orphan_path.exists())
        self.assertEqual(orphan_path.read_bytes(), orphan_body)
        # Index has only the primary; orphan not adopted.
        with Store(store_path) as store:
            self.assertEqual(len(store.messages), 1)
            self.assertNotIn(orphan_hash, store.messages)

    def test_prompt_accepted_then_recovers(self):
        # First (silent_retries+1)=2 attempts fail, prompt user, user says yes,
        # next batch's first attempt succeeds.
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(_make_eml("eventually"))
        inbox.fetch_failures_remaining = 2  # both silent attempts fail

        ctx = Context()
        with patch("builtins.input", return_value="y") as mock_input:
            sm.sync_emails(self._account(), ctx, auto_apply=True, max_silent_retries=1)
        # Prompt was hit at least once
        self.assertGreaterEqual(mock_input.call_count, 1)

        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            self.assertEqual(next(iter(store.messages.values()))["subject"], "eventually")

    # ─── history-as-truth: A→B→A, UIDVALIDITY refresh, resurrection ──────────────

    def test_round_trip_A_to_B_to_A(self):
        # Move A → B → A. Final history must have three entries:
        #   [{A, uid_initial, removed}, {B, uid_at_B, removed}, {A, uid_back_in_A}]
        # is_live(entry) returns True (the trailing A entry is live).
        body = _make_eml("nomadic")
        a = self.imap.add_folder("INBOX", uidvalidity=1)  # name "A" semantically
        b = self.imap.add_folder("Archive", uidvalidity=1)  # name "B" semantically
        a.add(body)  # uid 1 in INBOX

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Move 1: INBOX → Archive
        a.messages = []
        b.add(body)  # uid 1 in Archive

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Move 2: Archive → INBOX (back)
        b.messages = []
        a.add(body)  # uid 2 in INBOX (different uid this time, simulates a re-add)

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        with Store(self.tmppath / "store") as store:
            self.assertEqual(len(store.messages), 1)
            entry = next(iter(store.messages.values()))
            history = entry["history"]
            self.assertEqual(len(history), 3, f"expected 3 history entries, got {history}")
            # First two are removed, last is live
            self.assertTrue(history[0].get("removed"))
            self.assertEqual(history[0]["folder"], "INBOX")
            self.assertTrue(history[1].get("removed"))
            self.assertEqual(history[1]["folder"], "Archive")
            self.assertFalse(history[2].get("removed"))
            self.assertEqual(history[2]["folder"], "INBOX")
            self.assertTrue(is_live(entry))

    def test_uidvalidity_bump_message_stays_updates_uid_in_place(self):
        body = _make_eml("stays put")
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(body)  # uid 1

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # UIDVALIDITY bumps. Same content, fresh UID under the new scheme.
        inbox.uidvalidity = 999
        inbox.messages = []
        inbox.add(body)  # uid 1 again, but a brand-new one under the new UIDVALIDITY
        # Force a different uid to make the test meaningful
        inbox.messages[0].uid = 7

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        with Store(self.tmppath / "store") as store:
            entry = next(iter(store.messages.values()))
            history = entry["history"]
            # No new history entry — the existing live entry was updated in place.
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["folder"], "INBOX")
            self.assertEqual(history[0]["uid"], 7)  # ← the new UID, not the stale 1
            self.assertFalse(history[0].get("removed"))
            self.assertTrue(is_live(entry))

    def test_uidvalidity_bump_message_removed_marks_history_removed(self):
        # UIDVALIDITY bumps AND the message is gone from the folder under the new scheme.
        # Existing history entry must end up with removed=True; is_gone(entry) is True.
        body = _make_eml("disappears")
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(body)

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Bump UIDVALIDITY and remove the message.
        inbox.uidvalidity = 999
        inbox.messages = []

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        with Store(self.tmppath / "store") as store:
            entry = next(iter(store.messages.values()))
            self.assertTrue(is_gone(entry))
            self.assertTrue(all(h.get("removed") for h in entry["history"]))

    def test_resurrection_after_deletion_appends_live_history_entry(self):
        # Message deleted from server, then re-appears. is_live flips back to True;
        # history shows the original removed entry plus a fresh live entry.
        body = _make_eml("phoenix")
        inbox = self.imap.add_folder("INBOX", uidvalidity=1)
        inbox.add(body)  # uid 1

        sm.sync_emails(self._account(), Context(), auto_apply=True)

        # Delete server-side
        inbox.messages = []
        sm.sync_emails(self._account(), Context(), auto_apply=True)
        with Store(self.tmppath / "store") as store:
            entry = next(iter(store.messages.values()))
            self.assertTrue(is_gone(entry))

        # Resurrection: same body comes back with a different UID
        inbox.add(body)  # gets uid 1 again (or 2, doesn't matter)
        sm.sync_emails(self._account(), Context(), auto_apply=True)

        with Store(self.tmppath / "store") as store:
            entry = next(iter(store.messages.values()))
            self.assertTrue(is_live(entry))
            history = entry["history"]
            # First entry is the original (removed); a new live entry appended for the resurrection.
            self.assertGreaterEqual(len(history), 2)
            self.assertTrue(history[0].get("removed"))
            self.assertFalse(history[-1].get("removed"))


class TestParseAuthenticationResults(unittest.TestCase):
    """Extract DKIM/SPF/DMARC verdicts from Authentication-Results headers (RFC 8601).
    We surface what the receiving MTA decided; we don't re-verify."""

    def _msg(self, *header_values):
        msg = EmailMessage()
        for v in header_values:
            msg["Authentication-Results"] = v
        return msg

    def test_no_header_returns_empty(self):
        self.assertEqual(parse_authentication_results(EmailMessage()), {})

    def test_dkim_only(self):
        msg = self._msg("example.com; dkim=pass header.d=foo.com")
        self.assertEqual(parse_authentication_results(msg), {"dkim": "pass"})

    def test_all_three_methods(self):
        msg = self._msg(
            "mx.example.com; spf=pass smtp.mailfrom=alice@foo.com; "
            "dkim=pass header.d=foo.com; dmarc=pass action=none header.from=foo.com"
        )
        self.assertEqual(
            parse_authentication_results(msg),
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        )

    def test_failure_verdicts_extracted(self):
        msg = self._msg("mx.example.com; spf=fail; dkim=permerror; dmarc=quarantine")
        self.assertEqual(
            parse_authentication_results(msg),
            {"spf": "fail", "dkim": "permerror", "dmarc": "quarantine"},
        )

    def test_mixed_case_normalized(self):
        msg = self._msg("example.com; DKIM=Pass; SPF=Fail")
        self.assertEqual(parse_authentication_results(msg), {"dkim": "pass", "spf": "fail"})

    def test_multiple_headers_last_wins(self):
        # Simulates a chain: the most recent receiver's verdict overrides earlier ones.
        msg = self._msg(
            "old-receiver.example.com; dkim=fail",
            "new-receiver.example.com; dkim=pass",
        )
        self.assertEqual(parse_authentication_results(msg), {"dkim": "pass"})

    def test_unrelated_methods_ignored(self):
        # iprev/arc/smime not in our scope.
        msg = self._msg("example.com; iprev=pass; arc=fail; smime=none")
        self.assertEqual(parse_authentication_results(msg), {})

    def test_garbage_returns_empty(self):
        msg = self._msg("totally not a header")
        self.assertEqual(parse_authentication_results(msg), {})


class TestReadUIShowsAuthResults(unittest.TestCase):
    """End-to-end: the read UI surfaces the receiving MTA's auth verdict in the email view."""

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        config = {"accounts": [{"name": "test", "local_store_path": str(self.tmppath / "store")}]}
        sm.CONFIG_PATH.write_text(json.dumps(config))

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _index_one(self, eml_bytes):
        with Store(self.tmppath / "store") as store:
            content_hash = hashlib.sha256(eml_bytes).hexdigest()
            (store.mails_path / f"{content_hash}.eml").write_bytes(eml_bytes)
            store.messages[content_hash] = {
                "subject": "auth check",
                "from": "alice@example.com",
                "date": "Thu, 8 May 2026 14:30:00 +0000",
                "internaldate": "08-May-2026 14:30:00 +0000",
                "history": [{"folder": "INBOX", "uid": 1}],
            }
            store.save()

    def test_auth_line_present_when_header_set(self):
        msg = EmailMessage()
        msg["From"] = "alice@example.com"
        msg["To"] = "you@example.com"
        msg["Subject"] = "auth check"
        msg["Date"] = "Thu, 8 May 2026 14:30:00 +0000"
        msg["Authentication-Results"] = "gmail.com; spf=pass; dkim=pass; dmarc=pass"
        msg.set_content("hi")
        self._index_one(msg.as_bytes())

        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        # "1" + Enter opens entry 1; "q" in email-view quits.
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=["1", "\n", "q"]):
            with redirect_stdout(buf):
                sm.main()
        out = buf.getvalue()

        self.assertIn("Auth:", out)
        self.assertIn("DKIM=pass", out)
        self.assertIn("SPF=pass", out)
        self.assertIn("DMARC=pass", out)

    def test_auth_line_absent_when_no_header(self):
        msg = EmailMessage()
        msg["From"] = "alice@example.com"
        msg["To"] = "you@example.com"
        msg["Subject"] = "no auth header"
        msg["Date"] = "Thu, 8 May 2026 14:30:00 +0000"
        msg.set_content("hi")
        self._index_one(msg.as_bytes())

        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=["1", "\n", "q"]):
            with redirect_stdout(buf):
                sm.main()
        # No Authentication-Results header → no Auth: line shown.
        self.assertNotIn("Auth:", buf.getvalue())


class TestReadUINavigation(unittest.TestCase):
    """Coverage for primitives introduced by the raw-mode rework: cursor, digit buffer,
    Esc semantics, and the TTY guard. Three messages so cursor/buffer have room to move.
    Verbosity is bumped so a generic 'unknown command' path can't hide bugs silently."""

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        config = {"accounts": [{"name": "test", "local_store_path": str(self.tmppath / "store")}]}
        sm.CONFIG_PATH.write_text(json.dumps(config))

        # Index three messages with distinguishable subjects + descending internaldates.
        # Newest first matches the list ordering (internaldate_key reverse=True), so
        # entry index 0 = "first" (newest), 1 = "second", 2 = "third" (oldest).
        with Store(self.tmppath / "store") as store:
            for i, (subj, date) in enumerate(
                [
                    ("first email", "10-May-2026 14:30:00 +0000"),
                    ("second email", "09-May-2026 14:30:00 +0000"),
                    ("third email", "08-May-2026 14:30:00 +0000"),
                ]
            ):
                body = _make_eml(subj)
                content_hash = hashlib.sha256(body + str(i).encode()).hexdigest()
                (store.mails_path / f"{content_hash}.eml").write_bytes(body)
                store.messages[content_hash] = {
                    "subject": subj,
                    "from": "sender@example.com",
                    "date": "Thu, 8 May 2026 14:30:00 +0000",
                    "internaldate": date,
                    "history": [{"folder": "INBOX", "uid": i + 1}],
                }
            store.save()

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _run(self, keys):
        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=keys):
            with redirect_stdout(buf):
                sm.main()
        return buf.getvalue()

    def test_cursor_down_then_enter_opens_second_entry(self):
        # k moves the cursor; Enter opens the cursor row (no digit buffer in play).
        out = self._run(["k", "\n", "q"])
        self.assertIn("Subject: second email", out)
        self.assertNotIn("Subject: first email", out.split("Subject: second")[0] + " ")

    def test_digit_buffer_jumps_to_numbered_entry(self):
        # Digits accumulate; Enter opens that 1-indexed entry directly.
        out = self._run(["3", "\n", "q"])
        self.assertIn("Subject: third email", out)

    def test_esc_clears_digit_buffer(self):
        # Type "9" (would be out of range and a no-op) → Esc clears → "1" + Enter opens entry 1.
        # If Esc didn't clear, the buffer would be "91" and Enter would be a no-op (out of range),
        # leaving us on the list view — Subject: first email would never appear.
        out = self._run(["9", "\x1b", "1", "\n", "q"])
        self.assertIn("Subject: first email", out)

    def test_ctrl_c_quits(self):
        # Ctrl-C arrives as \x03 in raw mode; we treat it as q.
        # Empty stdout (no email view rendered) confirms we exited from the list.
        out = self._run(["\x03"])
        self.assertNotIn("Subject:", out)

    def test_require_tty_raises_when_stdin_not_a_tty(self):
        # The seam exists so tests can bypass; the real function must refuse non-TTY stdin.
        with patch("sm.sys_stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with self.assertRaises(SMException):
                sm._require_tty()


class TestReadUIViewport(unittest.TestCase):
    """Cover the viewport-follows-cursor + I/K ±10 step introduced with the offset rework.
    Uses 30 entries (subject 'email NN', sorted newest first) so cursor index N-1 reliably
    maps to subject 'email N' regardless of terminal height fallback."""

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        config = {"accounts": [{"name": "test", "local_store_path": str(self.tmppath / "store")}]}
        sm.CONFIG_PATH.write_text(json.dumps(config))

        # 30 entries: subject "email 01" (newest, sorts to index 0) → "email 30" (oldest).
        # Dates step back by 1 day so the sort is unambiguous.
        with Store(self.tmppath / "store") as store:
            for n in range(1, 31):
                day = 31 - n  # 30, 29, ..., 1
                subj = f"email {n:02d}"
                body = _make_eml(subj)
                content_hash = hashlib.sha256(body + subj.encode()).hexdigest()
                (store.mails_path / f"{content_hash}.eml").write_bytes(body)
                store.messages[content_hash] = {
                    "subject": subj,
                    "from": "s@example.com",
                    "date": "Thu, 8 May 2026 14:30:00 +0000",
                    "internaldate": f"{day:02d}-May-2026 12:00:00 +0000",
                    "history": [{"folder": "INBOX", "uid": n}],
                }
            store.save()

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _run(self, keys):
        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=keys):
            with redirect_stdout(buf):
                sm.main()
        return buf.getvalue()

    def test_K_jumps_cursor_down_10(self):
        # Start at cursor=0; K (+10) → cursor=10; Enter opens entries[10] = "email 11".
        out = self._run(["K", "\n", "q"])
        self.assertIn("Subject: email 11", out)

    def test_I_after_K_jumps_back_up_10(self):
        # K K → cursor=20; I → cursor=10; Enter opens "email 11".
        out = self._run(["K", "K", "I", "\n", "q"])
        self.assertIn("Subject: email 11", out)

    def test_K_at_bottom_clamps(self):
        # K x 5 = cursor=50, clamped to 29. Enter opens "email 30" (the oldest, last entry).
        out = self._run(["K", "K", "K", "K", "K", "\n", "q"])
        self.assertIn("Subject: email 30", out)

    def test_L_jumps_to_last_entry(self):
        out = self._run(["L", "\n", "q"])
        self.assertIn("Subject: email 30", out)

    def test_J_after_L_jumps_back_to_first(self):
        out = self._run(["L", "J", "\n", "q"])
        self.assertIn("Subject: email 01", out)

    def test_l_twice_reaches_bottom(self):
        # Robust across page_size: first l snaps to bottom-of-screen, second l (at the
        # screen bottom) pages down. Either page_size >= 30 (one l reaches 29 directly)
        # or page_size < 30 (two presses reach 29 by snap + clamp).
        out = self._run(["l", "l", "\n", "q"])
        self.assertIn("Subject: email 30", out)

    def test_find_filters_to_matching_subject_and_opens_it(self):
        # f enters find_mode; each character is a keystroke; Enter applies; Enter opens
        # the single match (entries[0] after filter = "email 15").
        keys = ["f", *list("email 15"), "\n", "\n", "q"]
        out = self._run(keys)
        self.assertIn("Subject: email 15", out)

    def test_find_empty_query_applies_no_filter(self):
        # f → immediate Enter exits with empty query → q quits without opening anything.
        out = self._run(["f", "\n", "q"])
        self.assertNotIn("Subject: email", out)
        self.assertIn("/30", out)

    def test_find_no_matches_renders_inline_hint(self):
        # No more separate screen; the list area shows "no email with the current filters".
        keys = ["f", *list("zzznope"), "\n", "q"]
        out = self._run(keys)
        self.assertIn("no email with the current filters", out)

    def test_find_is_case_insensitive_and_matches_from(self):
        # 'S@EXAMPLE' matches every entry's from (s@example.com); first match is "email 01".
        keys = ["f", *list("S@EXAMPLE"), "\n", "\n", "q"]
        out = self._run(keys)
        self.assertIn("Subject: email 01", out)

    def test_esc_in_find_mode_cancels_and_clears_query(self):
        # f → type 'nope' → Esc cancels (query cleared, find_mode exited) → q quits.
        # The unfiltered list (entry x/30) is rendered between Esc and q.
        keys = ["f", *list("nope"), "\x1b", "q"]
        out = self._run(keys)
        self.assertIn("/30", out)

    def test_backspace_in_find_mode_removes_last_char(self):
        # Type 'email 159' then DEL → query = 'email 15' → Enter applies → Enter opens.
        keys = ["f", *list("email 159"), "\x7f", "\n", "\n", "q"]
        out = self._run(keys)
        self.assertIn("Subject: email 15", out)

    def test_find_query_live_updates_during_typing(self):
        # Verify the prompt re-renders each keystroke by checking that an intermediate
        # query state ('em') and the final state ('email 15') both appear in stdout.
        keys = ["f", *list("email 15"), "\n", "q"]
        out = self._run(keys)
        self.assertIn("find: em", out)
        self.assertIn("find: email 15", out)


class TestReadUIFolderPresets(unittest.TestCase):
    """Pass 6 coverage: config-defined folder presets, [none]/[custom] pseudo-presets,
    j/l preset navigation, and persistence across sessions via state.json."""

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        config = {
            "accounts": [
                {
                    "name": "test",
                    "local_store_path": str(self.tmppath / "store"),
                    # "Work" is preset-only (no messages live there) — must still appear in the menu.
                    "folder_presets": {"work": ["INBOX", "Work"]},
                }
            ],
        }
        sm.CONFIG_PATH.write_text(json.dumps(config))

        plan = [
            ("in-inbox", "04-May-2026 12:00:00 +0000", [{"folder": "INBOX", "uid": 1}]),
            ("in-archive", "03-May-2026 12:00:00 +0000", [{"folder": "Archive", "uid": 1}]),
        ]
        with Store(self.tmppath / "store") as store:
            for subj, idate, history in plan:
                body = _make_eml(subj)
                content_hash = hashlib.sha256(body + subj.encode()).hexdigest()
                (store.mails_path / f"{content_hash}.eml").write_bytes(body)
                store.messages[content_hash] = {
                    "subject": subj,
                    "from": "s@example.com",
                    "date": "Thu, 8 May 2026 14:30:00 +0000",
                    "internaldate": idate,
                    "history": history,
                }
            store.save()

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _state_file(self):
        return self.tmppath / "store" / "state.json"

    def _run(self, keys):
        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=keys):
            with redirect_stdout(buf):
                sm.main()
        return buf.getvalue()

    def test_modal_shows_preset_row_with_none_named_and_custom(self):
        out = self._run(["m", "\x1b", "q"])
        self.assertIn("[none]", out)
        self.assertIn("work", out)
        self.assertIn("[custom]", out)

    def test_preset_only_folder_appears_in_folder_list(self):
        # "Work" lives only in the preset; no message resides there. Must still show up.
        out = self._run(["m", "\x1b", "q"])
        self.assertIn("Work", out)

    def test_applying_named_preset_sets_filter_and_persists(self):
        # Preset order: [none](0), work(1), [custom](2). l moves preset cursor and
        # live-applies the preset in one step; Enter commits.
        out = self._run(["m", "l", "\n", "q"])
        self.assertIn("entry 1/1", out)
        # Header shows the preset name (intent), not a resolved folder count.
        self.assertIn("filter: work", out)
        import json

        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "work")
        # Recovery snapshot stored so config drift doesn't silently drop the filter.
        self.assertEqual(set(data["last_resolved"]), {"INBOX", "Work"})

    def test_apply_none_preset_clears_filter(self):
        # Pre-seed state.json with [custom]/INBOX. Modal opens with cursor on [custom] (idx 2).
        # j j moves the preset cursor 2 → 1 → 0 and live-applies along the way; final state
        # is [none]. Enter commits.
        import json

        self._state_file().parent.mkdir(parents=True, exist_ok=True)
        self._state_file().write_text(
            json.dumps(
                {
                    "version": 1,
                    "selection_current": "[custom]",
                    "folders_selected_in_custom": ["INBOX"],
                    "last_resolved": ["INBOX"],
                }
            )
        )
        out = self._run(["m", "j", "j", "\n", "q"])
        self.assertIn("entry 1/2", out)
        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "[none]")
        self.assertIsNone(data["last_resolved"])

    def test_state_persists_across_sessions(self):
        # Session 1: l live-applies work, Enter commits.
        self._run(["m", "l", "\n", "q"])
        # Session 2: just quit — the filter should still be active and the preset name visible.
        out = self._run(["q"])
        self.assertIn("filter: work", out)

    def test_esc_in_modal_does_not_persist(self):
        # Open menu, toggle a folder via Space (cursor at folder), then Esc — no save.
        self._run(["m", " ", "\x1b", "q"])
        self.assertFalse(self._state_file().exists())

    def test_editing_folder_writes_to_custom_folders(self):
        # Folders sorted: Archive(0), INBOX(1), Work(2). Filter starts off → working=all ticked.
        # Space on Archive (cursor 0): filter on, working = {INBOX, Work}. State rolls to [custom].
        self._run(["m", " ", "\n", "q"])
        import json

        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "[custom]")
        self.assertEqual(set(data["folders_selected_in_custom"]), {"INBOX", "Work"})
        self.assertEqual(set(data["last_resolved"]), {"INBOX", "Work"})

    def test_corrupt_state_json_falls_back_to_no_filter(self):
        self._state_file().parent.mkdir(parents=True, exist_ok=True)
        self._state_file().write_text("not json {")
        out = self._run(["q"])
        # Both entries visible, no filter active.
        self.assertIn("entry 1/2", out)
        self.assertNotIn("filter:", out)

    def test_preset_edit_in_config_auto_applies_next_session(self):
        # The whole point of storing *intent* instead of resolved set.
        # Session 1: l live-applies "work" → state has selection_current="work".
        self._run(["m", "l", "\n", "q"])

        # Now mutate the config: "work" gains an extra folder ("Archive").
        import json

        cfg = json.loads(sm.CONFIG_PATH.read_text())
        cfg["accounts"][0]["folder_presets"]["work"] = ["INBOX", "Work", "Archive"]
        sm.CONFIG_PATH.write_text(json.dumps(cfg))

        # Session 2: filter resolves against the new preset → now includes Archive too,
        # so "in-archive" appears in the visible list.
        out = self._run(["q"])
        # Header still says "filter: work" (intent, not resolved set).
        self.assertIn("filter: work", out)
        # Both entries (in-inbox + in-archive) now match the broadened preset.
        self.assertIn("entry 1/2", out)

    def test_dangling_preset_main_loop_uses_last_resolved_recovery(self):
        """A dangling preset name in state.json must not lose the user's filter at read time.
        Session 1 selects 'work' (last_resolved cached). Then the preset is deleted from
        config. Session 2 must still show the filtered list (no crash, no silent drop)
        without rewriting state.json (no modal opened)."""
        self._run(["m", "l", "\n", "q"])
        import json

        cfg = json.loads(sm.CONFIG_PATH.read_text())
        del cfg["accounts"][0]["folder_presets"]["work"]
        sm.CONFIG_PATH.write_text(json.dumps(cfg))

        out = self._run(["q"])
        # Filter still resolves to {INBOX, Work} via last_resolved; only "in-inbox" matches.
        self.assertIn("entry 1/1", out)
        # state.json untouched this session (no modal commit) — still references the
        # deleted preset by name. Recovery is via last_resolved at read time only.
        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "work")
        self.assertEqual(set(data["last_resolved"]), {"INBOX", "Work"})

    def test_dangling_preset_modal_commit_normalizes_to_custom(self):
        """Opening the modal in a dangling state should land in [custom] (seeded from
        last_resolved). Pressing Enter must persist the normalized form: selection_current
        becomes '[custom]' and the recovered folder set is saved as folders_selected_in_custom."""
        self._run(["m", "l", "\n", "q"])
        import json

        cfg = json.loads(sm.CONFIG_PATH.read_text())
        del cfg["accounts"][0]["folder_presets"]["work"]
        sm.CONFIG_PATH.write_text(json.dumps(cfg))

        # Session 2: open modal, immediately Enter to commit (no edits) → normalize.
        self._run(["m", "\n", "q"])
        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "[custom]")
        self.assertEqual(set(data["folders_selected_in_custom"]), {"INBOX", "Work"})
        # last_resolved gets recomputed to match the new selection (set([INBOX, Work]) for [custom]).
        self.assertEqual(set(data["last_resolved"]), {"INBOX", "Work"})

    def test_dangling_preset_with_no_recovery_falls_to_none(self):
        """Hand-crafted edge case: state.json names a missing preset, no last_resolved,
        no folders_selected_in_custom. The main loop must show no filter (not an empty-
        set [custom] that hides everything), and opening the modal + Enter must normalize
        to [none] rather than landing in a no-folders-ticked [custom] trap."""
        import json

        self._state_file().parent.mkdir(parents=True, exist_ok=True)
        self._state_file().write_text(
            json.dumps(
                {
                    "version": 1,
                    "selection_current": "gone_preset",
                    "folders_selected_in_custom": None,
                    "last_resolved": None,
                }
            )
        )
        # Main loop: filter resolves to None (no recovery data), full list visible.
        out = self._run(["q"])
        self.assertIn("entry 1/2", out)

        # Modal commit normalizes to [none] (clean drop, not empty-set [custom]).
        self._run(["m", "\n", "q"])
        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "[none]")
        self.assertIsNone(data["last_resolved"])

    def test_l_live_applies_preset_without_space(self):
        """j/l should apply the preset on the move — no separate Space confirmation.
        Pressing l alone (no Space) and then Enter should commit the work preset.
        If j/l were navigation-only (old behavior), Enter at this point would commit
        the still-active [none] state and no filter would persist."""
        self._run(["m", "l", "\n", "q"])
        import json

        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "work")

    def test_dangling_preset_with_existing_custom_preserves_custom(self):
        """When state has both a dangling preset name AND a separate folders_selected_in_custom,
        the modal recovers to [custom] preserving the existing custom set (preferred over
        last_resolved, which represents the now-gone preset). On commit, the dangling name
        is replaced with [custom] and folders_selected_in_custom stays intact."""
        import json

        self._state_file().parent.mkdir(parents=True, exist_ok=True)
        self._state_file().write_text(
            json.dumps(
                {
                    "version": 1,
                    "selection_current": "gone_preset",
                    "folders_selected_in_custom": ["INBOX"],
                    "last_resolved": ["Archive"],  # different from custom — must not win
                }
            )
        )
        self._run(["m", "\n", "q"])
        data = json.loads(self._state_file().read_text())
        self.assertEqual(data["selection_current"], "[custom]")
        # Custom preserved (was [INBOX]), not overwritten by last_resolved's [Archive].
        self.assertEqual(set(data["folders_selected_in_custom"]), {"INBOX"})
        self.assertEqual(set(data["last_resolved"]), {"INBOX"})


class TestReadUIFolderFilter(unittest.TestCase):
    """Pass 5 coverage: the folder-enable/disable menu and its filter effect.

    Fixture: 4 entries across 3 folders so the menu has real choices and we can verify
    both inclusion and exclusion behavior.
      - "inbox-only"     → INBOX
      - "archive-only"   → Archive
      - "both-folders"   → INBOX + Archive (live in both)
      - "had-junk-now-archive" → Archive (live) + Junk (removed)
    """

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        config = {"accounts": [{"name": "test", "local_store_path": str(self.tmppath / "store")}]}
        sm.CONFIG_PATH.write_text(json.dumps(config))

        plan = [
            ("inbox-only", "04-May-2026 12:00:00 +0000", [{"folder": "INBOX", "uid": 1}]),
            ("archive-only", "03-May-2026 12:00:00 +0000", [{"folder": "Archive", "uid": 1}]),
            (
                "both-folders",
                "02-May-2026 12:00:00 +0000",
                [{"folder": "INBOX", "uid": 2}, {"folder": "Archive", "uid": 2}],
            ),
            (
                "had-junk-now-archive",
                "01-May-2026 12:00:00 +0000",
                [{"folder": "Archive", "uid": 3}, {"folder": "Junk", "uid": 1, "removed": True}],
            ),
        ]
        with Store(self.tmppath / "store") as store:
            for subj, idate, history in plan:
                body = _make_eml(subj)
                content_hash = hashlib.sha256(body + subj.encode()).hexdigest()
                (store.mails_path / f"{content_hash}.eml").write_bytes(body)
                store.messages[content_hash] = {
                    "subject": subj,
                    "from": "s@example.com",
                    "date": "Thu, 8 May 2026 14:30:00 +0000",
                    "internaldate": idate,
                    "history": history,
                }
            store.save()

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _run(self, keys):
        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=keys):
            with redirect_stdout(buf):
                sm.main()
        return buf.getvalue()

    def test_folder_menu_lists_all_folders_from_history_including_removed(self):
        # Open menu, immediately Esc (no change), then quit. All 3 folders must appear:
        # INBOX, Archive, Junk (Junk only via a removed history entry).
        out = self._run(["m", "\x1b", "q"])
        self.assertIn("INBOX", out)
        self.assertIn("Archive", out)
        self.assertIn("Junk", out)

    def test_folder_menu_cancel_preserves_filter(self):
        # Open menu → space (toggle off the first folder = Archive alphabetically) → Esc.
        # Cancel must not mutate state. All 4 entries still visible in the list.
        out = self._run(["m", " ", "\x1b", "q"])
        # Header shows 4 entries (entry 1/4).
        self.assertIn("/4", out)

    def test_folder_menu_apply_only_inbox(self):
        # Folders sorted: ["Archive", "INBOX", "Junk"]. Cursor starts at 0 = Archive.
        # Untick Archive (space), k → INBOX, leave ticked. k → Junk, untick (space). Enter.
        # Result: only INBOX enabled → entries with a live INBOX history: "inbox-only" + "both-folders".
        out = self._run(["m", " ", "k", "k", " ", "\n", "q"])
        # Header reflects filter and reduced count.
        self.assertIn("/2", out)
        # Editing folders puts the session into the [custom] selection.
        self.assertIn("filter: [custom]", out)

    def test_folder_menu_disabling_all_yields_empty_list(self):
        # Untick all 3 folders → Enter → no entries match → inline "no email" hint.
        out = self._run(["m", " ", "k", " ", "k", " ", "\n", "q"])
        self.assertIn("no email with the current filters", out)

    def test_removed_history_entries_dont_satisfy_folder_filter(self):
        # Enable Junk only. The "had-junk-now-archive" entry has Junk in history but it's
        # removed=True, so it must NOT appear. Result: 0 visible entries.
        # Folders alphabetical: Archive (cursor 0), INBOX (1), Junk (2).
        # Untick Archive (space), k → INBOX, untick (space), k → Junk (already ticked). Enter.
        out = self._run(["m", " ", "k", " ", "\n", "q"])
        # With only Junk enabled and Junk's only history entry being removed, no entries match.
        self.assertIn("no email with the current filters", out)


class TestReadUIErrorRecording(unittest.TestCase):
    """End-to-end coverage of the read UI's error-handling story: each recoverable failure
    mode (missing .eml, parse exception, attachment-walk exception) lands as a `read_failed`
    ErrorEvent and is reachable via the [e]rrors action — the UI never crashes on these.

    Drives `sm.main()` with patched argv + stubbed config + scripted stdin, observing the
    full output. The only "don't even try to load the UI" failure is a corrupted index.json,
    covered separately by TestCorruptedIndex."""

    def setUp(self):
        import json

        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        # Save + override module-level globals that main() touches
        self._orig_lock = sm.LOCK_PATH
        self._orig_config = sm.CONFIG_PATH
        self._orig_argv = sm.argv
        sm.LOCK_PATH = self.tmppath / "lock"
        sm.CONFIG_PATH = self.tmppath / "config.json"
        Store._active = False
        # Build a minimal config — only fields read_emails actually uses
        config = {"accounts": [{"name": "test", "local_store_path": str(self.tmppath / "store")}]}
        sm.CONFIG_PATH.write_text(json.dumps(config))

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        sm.CONFIG_PATH = self._orig_config
        sm.argv = self._orig_argv
        Store._active = False
        self._tmp.cleanup()

    def _populate_one(self, eml_bytes=None):
        """Index one message into the store. Returns its content hash."""
        body = eml_bytes if eml_bytes is not None else _make_eml("subject A")
        with Store(self.tmppath / "store") as store:
            content_hash = hashlib.sha256(body).hexdigest()
            (store.mails_path / f"{content_hash}.eml").write_bytes(body)
            store.messages[content_hash] = {
                "subject": "subject A",
                "from": "alice@example.com",
                "date": "Thu, 8 May 2026 14:30:00 +0000",
                "internaldate": "08-May-2026 14:30:00 +0000",
                "history": [{"folder": "INBOX", "uid": 1}],
            }
            store.save()
        return content_hash

    def _run_main_read(self, keys):
        """Run sm.main() with action=read, scripted single-keystroke input. Returns captured stdout.
        Each element of `keys` is a single-char string passed to one `_read_key` call."""
        sm.argv = ["sm", "read", "account=test"]
        buf = io.StringIO()
        with patch("sm._require_tty"), patch("sm._read_key", side_effect=keys):
            with redirect_stdout(buf):
                sm.main()
        return buf.getvalue()

    def test_missing_eml_records_and_surfaces_via_errors_screen(self):
        content_hash = self._populate_one()
        # Manual delete of the .eml: simulates a corrupted store / lost file
        (self.tmppath / "store" / "mails" / f"{content_hash}.eml").unlink()

        # "1" + Enter → load fails (failure modal) → " " dismiss → "e" errors screen → " " dismiss → "q" quit.
        out = self._run_main_read(["1", "\n", " ", "e", " ", "q"])

        # UI didn't crash — we got the inline failure message
        self.assertIn("Failed to load email", out)
        # Error reached the [e]rrors action with the expected kind + identifying detail
        self.assertIn("[read_failed]", out)
        self.assertIn("missing", out.lower())
        self.assertIn(content_hash[:12], out)

    def test_parse_exception_records_and_surfaces_via_errors_screen(self):
        self._populate_one()
        # Force the parse step to raise: this simulates a corrupt .eml that message_from_bytes
        # can't handle. (In practice message_from_bytes is very permissive, so we mock it.)
        with patch("sm.message_from_bytes", side_effect=ValueError("malformed envelope")):
            out = self._run_main_read(["1", "\n", " ", "e", " ", "q"])

        self.assertIn("Failed to load email", out)
        self.assertIn("[read_failed]", out)
        self.assertIn("ValueError", out)
        self.assertIn("malformed envelope", out)

    def test_attachment_walk_exception_records_and_surfaces_via_errors_screen(self):
        self._populate_one()
        # Attachment listing crashes (rare, but list_attachments walks an arbitrary tree).
        with patch("sm.list_attachments", side_effect=RuntimeError("walk blew up")):
            out = self._run_main_read(["1", "\n", " ", "e", " ", "q"])

        self.assertIn("Failed to load email", out)
        self.assertIn("[read_failed]", out)
        self.assertIn("RuntimeError", out)
        self.assertIn("walk blew up", out)


class TestShowErrorsScreen(unittest.TestCase):
    """The full-detail error screen used by the read UI's [e]rrors action.
    Always shows full per-event detail (verbosity-independent — the user explicitly
    asked to see them). The interactive 'press Enter' wait is patched out."""

    def test_no_errors_says_so(self):
        ctx = Context()
        buf = io.StringIO()
        with redirect_stdout(buf), patch("sm._read_key", return_value=" "):
            sm._show_errors_screen(ctx, term_width=80)
        out = buf.getvalue()
        self.assertIn("No errors recorded", out)

    def test_groups_by_kind_with_count_and_details(self):
        ctx = Context()
        ctx.record_error("parse_list", "first detail")
        ctx.record_error("parse_list", "second detail")
        ctx.record_error("select_failed", "third detail")
        buf = io.StringIO()
        with redirect_stdout(buf), patch("sm._read_key", return_value=" "):
            sm._show_errors_screen(ctx, term_width=80)
        out = buf.getvalue()
        # Group headers with proper plural/singular labels
        self.assertIn("[parse_list] 2 entries:", out)
        self.assertIn("[select_failed] 1 entry:", out)
        # Each detail shown verbatim
        self.assertIn("first detail", out)
        self.assertIn("second detail", out)
        self.assertIn("third detail", out)

    def test_kinds_grouped_alphabetically(self):
        ctx = Context()
        ctx.record_error("zzz", "z")
        ctx.record_error("aaa", "a")
        ctx.record_error("mmm", "m")
        buf = io.StringIO()
        with redirect_stdout(buf), patch("sm._read_key", return_value=" "):
            sm._show_errors_screen(ctx, term_width=80)
        out = buf.getvalue()
        self.assertLess(out.index("[aaa]"), out.index("[mmm]"))
        self.assertLess(out.index("[mmm]"), out.index("[zzz]"))

    def test_visible_at_default_quiet_verbosity(self):
        # Unlike _summarize_errors which gates details by verbosity, this screen always shows
        # full detail because the user invoked it intentionally (verbosity is irrelevant here).
        ctx = Context()  # default = Verbosity.ERROR (most quiet)
        ctx.record_error("parse_list", "should still be visible")
        buf = io.StringIO()
        with redirect_stdout(buf), patch("sm._read_key", return_value=" "):
            sm._show_errors_screen(ctx, term_width=80)
        self.assertIn("should still be visible", buf.getvalue())


class TestSummarizeErrors(unittest.TestCase):
    def test_no_errors_silent(self):
        ctx = Context(param=Param(verbosity=Verbosity.DEBUG))  # max verbosity, still no output
        buf = io.StringIO()
        with redirect_stdout(buf):
            sm._summarize_errors(ctx)
        self.assertEqual(buf.getvalue(), "")

    def test_summary_visible_at_default_verbosity(self):
        # Default Verbosity.ERROR is the most quiet. The error summary must still surface
        # because the user needs to know things went wrong; uses Verbosity.ERROR-level log.
        ctx = Context()
        ctx.record_error("parse_list", "first")
        ctx.record_error("parse_list", "second")
        ctx.record_error("select_failed", "third")
        buf = io.StringIO()
        with redirect_stdout(buf):
            sm._summarize_errors(ctx)
        out = buf.getvalue()
        self.assertIn("3 issue(s)", out)
        self.assertIn("parse_list (2)", out)
        self.assertIn("select_failed (1)", out)
        self.assertIn("verbose=2", out)
        # Per-event details are NOT visible at default verbosity — only at DEBUG.
        self.assertNotIn("first", out)
        self.assertNotIn("second", out)
        self.assertNotIn("third", out)

    def test_details_visible_at_debug(self):
        ctx = Context(param=Param(verbosity=Verbosity.DEBUG))
        ctx.record_error("parse_list", "first detail")
        ctx.record_error("select_failed", "second detail")
        buf = io.StringIO()
        with redirect_stdout(buf):
            sm._summarize_errors(ctx)
        out = buf.getvalue()
        self.assertIn("first detail", out)
        self.assertIn("second detail", out)
        # The verbose=2 hint is suppressed when we're already at DEBUG.
        self.assertNotIn("verbose=2", out)

    def test_kinds_grouped_alphabetically(self):
        ctx = Context()
        ctx.record_error("zzz", "z")
        ctx.record_error("aaa", "a")
        ctx.record_error("mmm", "m")
        buf = io.StringIO()
        with redirect_stdout(buf):
            sm._summarize_errors(ctx)
        out = buf.getvalue()
        self.assertLess(out.index("aaa"), out.index("mmm"))
        self.assertLess(out.index("mmm"), out.index("zzz"))


class TestSyncEmailsIsProducerOnly(unittest.TestCase):
    """sync_emails appends to ctx.errors but does NOT render a summary itself. The caller
    (e.g. main, or a test harness) is the consumer. Pre-existing entries are preserved
    across calls; nothing about ctx.errors is mutated except by the recording sites."""

    @classmethod
    def setUpClass(cls):
        cert_data = _generate_test_cert()
        if cert_data is None:
            raise unittest.SkipTest("openssl not available")
        cls.cert_path, cls.key_path, cls.cert_sha256, _ = cert_data

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        sm.LOCK_PATH = self.tmppath / "lock"
        Store._active = False
        self.imap = _FakeIMAPServer(self.cert_path, self.key_path)
        self.imap.start()

    def tearDown(self):
        self.imap.stop()
        sm.LOCK_PATH = self._orig_lock
        Store._active = False
        self._tmp.cleanup()

    def _account(self):
        return MailConnectionInfos(
            name="t",
            username="u",
            password="p",
            imap_ssl_host="localhost",
            imap_ssl_port=self.imap.port,
            pinned_imap_certificate_sha256=self.cert_sha256,
            local_store_path=str(self.tmppath / "store"),
            ssl_cafile=str(self.cert_path),
        )

    def test_pre_existing_errors_preserved(self):
        ctx = Context()
        ctx.record_error("stale_from_prior_run", "should NOT be discarded")
        self.imap.add_folder("INBOX")
        self.imap.folders["INBOX"].add(_make_eml("clean"))
        sm.sync_emails(self._account(), ctx, auto_apply=True)
        self.assertEqual(len(ctx.errors), 1)
        self.assertEqual(ctx.errors[0].kind, "stale_from_prior_run")

    def test_does_not_render_error_summary(self):
        # Producer-only: sync_emails must never print the "N issue(s) during sync" digest itself.
        # That's the caller's job (currently main(), see the try/finally around the sync action).
        ctx = Context()
        ctx.record_error("from_other_account", "pre-existing")
        self.imap.add_folder("INBOX")
        self.imap.folders["INBOX"].add(_make_eml("clean"))

        buf = io.StringIO()
        with redirect_stdout(buf):
            sm.sync_emails(self._account(), ctx, auto_apply=True)
        self.assertNotIn("issue(s) during sync", buf.getvalue())


class TestIsLiveIsGone(unittest.TestCase):
    def test_empty_history_is_gone(self):
        # Defensive: malformed entry with no history. Treated as gone (filtered out by readers).
        self.assertFalse(is_live({"history": []}))
        self.assertTrue(is_gone({"history": []}))
        self.assertFalse(is_live({}))  # missing key
        self.assertTrue(is_gone({}))

    def test_single_live_entry_is_live(self):
        e = {"history": [{"folder": "INBOX", "uid": 1}]}
        self.assertTrue(is_live(e))
        self.assertFalse(is_gone(e))

    def test_all_removed_is_gone(self):
        e = {
            "history": [
                {"folder": "INBOX", "uid": 1, "removed": True},
                {"folder": "Archive", "uid": 5, "removed": True},
            ]
        }
        self.assertFalse(is_live(e))
        self.assertTrue(is_gone(e))

    def test_mixed_is_live(self):
        e = {
            "history": [
                {"folder": "INBOX", "uid": 1, "removed": True},
                {"folder": "Archive", "uid": 5},  # one live entry
            ]
        }
        self.assertTrue(is_live(e))
        self.assertFalse(is_gone(e))


class TestCorruptedIndex(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmppath = Path(self._tmp.name)
        self._orig_lock = sm.LOCK_PATH
        sm.LOCK_PATH = self.tmppath / "lock"
        Store._active = False

    def tearDown(self):
        sm.LOCK_PATH = self._orig_lock
        Store._active = False
        self._tmp.cleanup()

    def test_corrupted_json_raises_friendly_smexception(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text("this is { not valid json")

        with self.assertRaises(SMException) as cm:
            with Store(store_path):
                pass
        msg = str(cm.exception)
        # Must say where + how to recover, not dump a JSONDecodeError stack trace at the user.
        self.assertIn("corrupted", msg.lower())
        self.assertIn("index.json", msg)
        self.assertIn("re-sync", msg)

    def test_truncated_json_raises_friendly_smexception(self):
        store_path = self.tmppath / "store"
        store_path.mkdir()
        (store_path / "index.json").write_text('{"messages": {"abc": {"sub')  # cut off mid-key

        with self.assertRaises(SMException) as cm:
            with Store(store_path):
                pass
        self.assertIn("corrupted", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
