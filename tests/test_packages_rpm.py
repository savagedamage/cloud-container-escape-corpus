"""RPM package-inventory parsing.

Two layers of evidence here, deliberately:

1. A REAL header blob captured from rockylinux:9-minimal
   (`tests/fixtures/rpm-blob-bash.bin` — bash 5.1.8-6.el9_1, x86_64, hnum=14).
   This anchors the format: it is what rpm actually writes, including the fact
   that the sqlite backend strips the 8-byte magic that the on-disk header has.
   A purely synthetic fixture would have "tested" a layout that never occurs —
   which is exactly the bug this file exists to prevent.
2. A small builder for synthetic headers, used only to exercise logic the real
   blob cannot (epochs, source-rpm filtering, malformed input).
"""

import sqlite3
import struct
from pathlib import Path

import pytest

from escape_corpus.packages import (
    APK_INSTALLED,
    DPKG_STATUS,
    RPM_SQLITE_PATHS,
    RPMTAG_ARCH,
    RPMTAG_EPOCH,
    RPMTAG_NAME,
    RPMTAG_RELEASE,
    RPMTAG_SOURCERPM,
    RPMTAG_VERSION,
    detect_format,
    inventory_from_merge,
    parse_rpm_header,
    parse_rpm_sqlite,
)

FIXTURE = Path(__file__).parent / "fixtures" / "rpm-blob-bash.bin"


def build_header(tags, with_magic=False):
    """Build an rpm header blob for the given {tag: (type, value)} mapping.

    value may be a str, an int (for the INT* types), or a list of either
    (STRING_ARRAY / multi-value int tags).
    """
    from escape_corpus.packages import _RPM_INT_TYPES

    data = bytearray()
    index = bytearray()
    for tag, (typ, value) in tags.items():
        offset = len(data)
        values = value if isinstance(value, list) else [value]
        count = len(values)
        if typ in _RPM_INT_TYPES:
            fmt = _RPM_INT_TYPES[typ]
            for v in values:
                data += struct.pack(fmt, v)
        else:
            for v in values:
                data += str(v).encode() + b"\x00"
        index += struct.pack(">IIII", tag, typ, offset, count)
    if with_magic:
        intro = b"\x8e\xad\xe8\x01" + b"\x00" * 4
    else:
        intro = b""
    return (intro + struct.pack(">II", len(tags), len(data)) + bytes(index) + bytes(data))


class TestRealBlob:
    """The captured fixture is the contract with reality."""

    def test_fixture_exists(self):
        assert FIXTURE.exists() and FIXTURE.stat().st_size > 1000

    def test_real_blob_parses_name_and_version(self):
        header = parse_rpm_header(FIXTURE.read_bytes())
        assert header[RPMTAG_NAME] == "bash"
        assert header[RPMTAG_VERSION] == "5.1.8"
        assert header[RPMTAG_RELEASE] == "6.el9_1"
        assert header[RPMTAG_ARCH] == "x86_64"

    def test_real_blob_in_sqlite_yields_a_versioned_package(self, tmp_path):
        db = tmp_path / "rpmdb.sqlite"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT,"
                     " blob BLOB NOT NULL)")
        conn.execute("INSERT INTO Packages (blob) VALUES (?)", (FIXTURE.read_bytes(),))
        conn.commit()
        conn.close()
        assert parse_rpm_sqlite(db) == {"bash": "5.1.8-6.el9_1"}

    def test_sqlite_backend_blob_has_no_magic(self):
        """Documents the trap: the stored blob starts at the index, not at the
        on-disk header magic, so a magic-only parser returns zero packages."""
        blob = FIXTURE.read_bytes()
        assert not blob.startswith(b"\x8e\xad\xe8")

    def test_reading_the_db_leaves_no_side_files(self, tmp_path):
        """Opened with immutable=1: a WAL/SHM must not be created beside the image
        being analysed (that would be a write into the artefact under study)."""
        db = tmp_path / "rpmdb.sqlite"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)")
        conn.execute("INSERT INTO Packages VALUES (1, ?)", (FIXTURE.read_bytes(),))
        conn.commit()
        conn.close()
        before = {p.name for p in tmp_path.iterdir()}
        parse_rpm_sqlite(db)
        assert {p.name for p in tmp_path.iterdir()} == before


class TestLayouts:
    def test_on_disk_layout_with_magic_also_parses(self):
        blob = build_header({
            RPMTAG_NAME: (6, "zlib"),
            RPMTAG_VERSION: (6, "1.2.11"),
            RPMTAG_RELEASE: (6, "40.el9"),
        }, with_magic=True)
        header = parse_rpm_header(blob)
        assert header[RPMTAG_NAME] == "zlib" and header[RPMTAG_RELEASE] == "40.el9"

    def test_both_layouts_agree_on_the_same_tags(self):
        tags = {RPMTAG_NAME: (6, "openssl"), RPMTAG_VERSION: (6, "3.0.7")}
        assert (parse_rpm_header(build_header(tags))[RPMTAG_NAME]
                == parse_rpm_header(build_header(tags, with_magic=True))[RPMTAG_NAME])

    def test_string_array_decodes_first_string(self):
        blob = build_header({RPMTAG_NAME: (8, ["a", "b"])})
        assert parse_rpm_header(blob)[RPMTAG_NAME] == "a"


class TestMalformedInput:
    def test_random_bytes_are_rejected(self):
        with pytest.raises(ValueError):
            parse_rpm_header(b"\x00" * 64)

    def test_truncated_header_is_rejected(self):
        blob = build_header({RPMTAG_NAME: (6, "x")})[:12]
        with pytest.raises(ValueError):
            parse_rpm_header(blob)

    def test_absurd_index_count_is_rejected(self):
        blob = struct.pack(">II", 999_999, 10) + b"\x00" * 40
        with pytest.raises(ValueError):
            parse_rpm_header(blob)

    def test_bad_blob_row_is_skipped_not_fatal(self, tmp_path):
        db = tmp_path / "rpmdb.sqlite"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)")
        conn.executemany("INSERT INTO Packages (blob) VALUES (?)",
                         [(b"garbage",), (FIXTURE.read_bytes(),)])
        conn.commit()
        conn.close()
        assert parse_rpm_sqlite(db) == {"bash": "5.1.8-6.el9_1"}


def _db(tmp_path, blobs):
    db = tmp_path / "rpmdb.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)")
    conn.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in blobs])
    conn.commit()
    conn.close()
    return db


class TestVersionComposition:
    def test_epoch_is_prefixed_when_nonzero(self, tmp_path):
        blob = build_header({RPMTAG_NAME: (6, "openssl-libs"), RPMTAG_VERSION: (6, "3.0.7"),
                             RPMTAG_RELEASE: (6, "24.el9"), RPMTAG_EPOCH: (4, 1)})
        assert parse_rpm_sqlite(_db(tmp_path, [blob])) == {"openssl-libs": "1:3.0.7-24.el9"}

    def test_zero_epoch_is_not_prefixed(self, tmp_path):
        blob = build_header({RPMTAG_NAME: (6, "bash"), RPMTAG_VERSION: (6, "5.1.8"),
                             RPMTAG_RELEASE: (6, "6.el9_1"), RPMTAG_EPOCH: (4, 0)})
        assert parse_rpm_sqlite(_db(tmp_path, [blob])) == {"bash": "5.1.8-6.el9_1"}

    def test_missing_epoch_is_fine(self, tmp_path):
        blob = build_header({RPMTAG_NAME: (6, "zlib"), RPMTAG_VERSION: (6, "1.2")})
        assert parse_rpm_sqlite(_db(tmp_path, [blob])) == {"zlib": "1.2"}

    def test_source_rpms_are_excluded(self, tmp_path):
        """A source rpm has SOURCERPM but no ARCH; counting it would inflate the
        inventory with packages that are not installed."""
        src = build_header({RPMTAG_NAME: (6, "bash"), RPMTAG_VERSION: (6, "5.1.8"),
                            RPMTAG_RELEASE: (6, "6.el9"), RPMTAG_SOURCERPM: (6, "")})
        binary = build_header({RPMTAG_NAME: (6, "bash"), RPMTAG_VERSION: (6, "5.1.8"),
                               RPMTAG_RELEASE: (6, "6.el9"), RPMTAG_ARCH: (6, "x86_64"),
                               RPMTAG_SOURCERPM: (6, "bash-5.1.8-6.el9.src.rpm")})
        assert parse_rpm_sqlite(_db(tmp_path, [src, binary])) == {"bash": "5.1.8-6.el9"}

    def test_missing_name_is_skipped(self, tmp_path):
        blob = build_header({RPMTAG_VERSION: (6, "1.0")})
        assert parse_rpm_sqlite(_db(tmp_path, [blob])) == {}


class TestDetectionAndIntegration:
    def test_detect_format_recognises_both_rpm_paths(self):
        for path in RPM_SQLITE_PATHS:
            assert detect_format({path: {}}) == "rpm"

    def test_dpkg_still_wins_when_both_are_present(self):
        assert detect_format({DPKG_STATUS: {}, RPM_SQLITE_PATHS[0]: {}}) == "dpkg"

    def test_inventory_from_merge_reads_a_real_rpmdb(self, tmp_path):
        db = _db(tmp_path, [FIXTURE.read_bytes()])
        merge = tmp_path / "merge"
        target = merge / RPM_SQLITE_PATHS[0].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(db.read_bytes())
        inv, fmt = inventory_from_merge(merge, {RPM_SQLITE_PATHS[0]: {}})
        assert fmt == "rpm" and inv == {"bash": "5.1.8-6.el9_1"}

    def test_berkeley_db_rpmdb_reports_unavailable_not_empty(self, tmp_path):
        """An old rpmdb (Packages as a berkeley db, not sqlite) must NOT look like
        a clean, dependency-free image."""
        merge = tmp_path / "merge"
        target = merge / RPM_SQLITE_PATHS[0].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"this is not a sqlite database")
        inv, fmt = inventory_from_merge(merge, {RPM_SQLITE_PATHS[0]: {}})
        assert (inv, fmt) == ({}, None)

    def test_missing_rpmdb_file_is_not_an_error(self, tmp_path):
        inv, fmt = inventory_from_merge(tmp_path, {RPM_SQLITE_PATHS[0]: {}})
        assert (inv, fmt) == ({}, None)

    def test_apk_and_dpkg_paths_still_work(self, tmp_path):
        assert detect_format({APK_INSTALLED: {}}) == "apk"
        assert detect_format({DPKG_STATUS: {}}) == "dpkg"
