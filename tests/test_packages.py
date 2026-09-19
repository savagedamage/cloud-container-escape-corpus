"""Tests for the package inventory and delta (escape_corpus.packages).

Kept DB-shape-faithful: the fixtures are trimmed copies of real dpkg `status`
and apk `installed` files, including the header/continuation lines that naive
parsers trip over.
"""

import json
from pathlib import Path

from escape_corpus.packages import (
    APK_INSTALLED,
    DPKG_STATUS,
    detect_format,
    diff_packages,
    inventory_from_merge,
    parse_apk_installed,
    parse_dpkg_status,
    summarise,
)

DPKG_REAL = """Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12813
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.36-9+deb12u4
Depends: libgcc-s1

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 continuation line that must not be mistaken for a field

Package: bash
Status: deinstall ok config-files
Version: 5.2.15-2+b2
"""

APK_REAL = """P:musl
V:1.2.4_git20230717-r5
A:x86_64
S:399472
I:622592
T:the musl c library (libc) implementation

P:busybox
V:1.36.1-r5
A:x86_64
T:Size optimized toolbox of many common UNIX utilities

P:zlib
V:1.3-r0
A:x86_64
"""


class TestDpkgParsing:
    def test_installed_packages_are_captured(self):
        pkgs = parse_dpkg_status(DPKG_REAL)
        assert pkgs["libc6"] == "2.36-9+deb12u4"
        assert pkgs["openssl"] == "3.0.11-1~deb12u2"

    def test_deinstalled_packages_are_excluded(self):
        assert "bash" not in parse_dpkg_status(DPKG_REAL)

    def test_continuation_lines_do_not_create_fields(self):
        """A wrapped Description line must not be read as Package:/Version:."""
        pkgs = parse_dpkg_status(DPKG_REAL)
        assert "continuation" not in " ".join(pkgs)

    def test_last_block_without_trailing_blank_line_is_flushed(self):
        pkgs = parse_dpkg_status("Package: solo\nStatus: install ok installed\nVersion: 1\n")
        assert pkgs == {"solo": "1"}

    def test_empty_input(self):
        assert parse_dpkg_status("") == {}


class TestApkParsing:
    def test_packages_are_captured(self):
        pkgs = parse_apk_installed(APK_REAL)
        assert pkgs == {"musl": "1.2.4_git20230717-r5", "busybox": "1.36.1-r5", "zlib": "1.3-r0"}

    def test_version_without_name_is_ignored(self):
        assert parse_apk_installed("V:1.0\n") == {}

    def test_empty_input(self):
        assert parse_apk_installed("") == {}


class TestDetection:
    def test_dpkg_image(self):
        assert detect_format({DPKG_STATUS: {}, "/bin/sh": {}}) == "dpkg"

    def test_apk_image(self):
        assert detect_format({APK_INSTALLED: {}}) == "apk"

    def test_image_without_a_known_package_db(self):
        assert detect_format({"/bin/sh": {}, "/usr/lib/libc.so": {}}) is None

    def test_rpm_only_image_is_recognised(self):
        """RPM images are parsed (rpmdb.sqlite). The *Berkeley-DB* rpmdb used by
        CentOS 7 and older is what remains unsupported, and that must report
        unavailable rather than empty — see tests/test_packages_rpm.py."""
        from escape_corpus.packages import RPM_SQLITE_PATHS
        assert detect_format({RPM_SQLITE_PATHS[0]: {}, "/usr/bin/bash": {}}) == "rpm"
        assert detect_format({RPM_SQLITE_PATHS[1]: {}}) == "rpm"


class TestInventoryFromMerge:
    def _image(self, tmp_path: Path, rel: str, text: str):
        d = tmp_path / "merge"
        target = d / rel.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return d

    def test_reads_dpkg_inventory(self, tmp_path):
        d = self._image(tmp_path, DPKG_STATUS, DPKG_REAL)
        inv, fmt = inventory_from_merge(d, {DPKG_STATUS: {}})
        assert fmt == "dpkg" and inv["openssl"] == "3.0.11-1~deb12u2"

    def test_reads_apk_inventory(self, tmp_path):
        d = self._image(tmp_path, APK_INSTALLED, APK_REAL)
        inv, fmt = inventory_from_merge(d, {APK_INSTALLED: {}})
        assert fmt == "apk" and "busybox" in inv

    def test_declared_but_missing_db_is_not_an_error(self, tmp_path):
        inv, fmt = inventory_from_merge(tmp_path, {DPKG_STATUS: {}})
        assert (inv, fmt) == ({}, None)

    def test_no_db_at_all(self, tmp_path):
        assert inventory_from_merge(tmp_path, {"/bin/sh": {}}) == ({}, None)


class TestDelta:
    def test_added_removed_upgraded(self):
        old = {"libssl3": "3.0.11", "bash": "5.2", "gone": "1.0"}
        new = {"libssl3": "3.0.13", "bash": "5.2", "added": "2.0"}
        delta = diff_packages(old, new)
        assert delta["added"] == ["added"]
        assert delta["removed"] == ["gone"]
        assert delta["upgraded"] == [{"package": "libssl3", "from": "3.0.11", "to": "3.0.13"}]
        assert delta["counts"] == {"added": 1, "removed": 1, "upgraded": 1}

    def test_identical_inventories_produce_an_empty_delta(self):
        inv = {"a": "1", "b": "2"}
        delta = diff_packages(inv, dict(inv))
        assert delta["counts"] == {"added": 0, "removed": 0, "upgraded": 0}

    def test_delta_is_sorted_and_deterministic(self):
        delta = diff_packages({}, {"z": "1", "a": "1", "m": "1"})
        assert delta["added"] == ["a", "m", "z"]

    def test_summary_mentions_the_format_and_counts(self):
        delta = diff_packages({"a": "1"}, {"a": "2"})
        assert summarise(delta, "dpkg") == "Packages (dpkg): +0 -0 ^ 1"

    def test_summary_is_honest_when_the_format_is_unknown(self):
        assert "unavailable" in summarise({}, None)


def test_delta_is_json_serialisable():
    """The delta rides inside the image-diff JSON output, so it must serialise."""
    delta = diff_packages({"a": "1"}, {"a": "2", "b": "1"})
    assert json.loads(json.dumps(delta))["counts"]["upgraded"] == 1
