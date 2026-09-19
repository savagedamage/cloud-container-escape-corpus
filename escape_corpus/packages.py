"""Installed-package inventory for flattened image filesystems.

The point: a file-level delta tells you 714 files changed; a package-level delta
tells you *which components* changed and in which direction, which is what an
operator actually triages ("libssl 3.0.11 → 3.0.13" beats "714 files").

Deliberately stdlib-only — no syft/grype binary required. Parsers cover the two
package databases that appear in the overwhelming majority of container images:

- dpkg   → /var/lib/dpkg/status   (Debian, Ubuntu)
- apk    → /lib/apk/db/installed  (Alpine)

RPM (rpmdb.sqlite / Berkeley DB) is NOT parsed: it needs a sqlite/rpm binding and
an image-level probe, so those images report an empty inventory and the delta
says so explicitly rather than silently looking clean.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DPKG_STATUS = "/var/lib/dpkg/status"
APK_INSTALLED = "/lib/apk/db/installed"


def parse_dpkg_status(text: str) -> Dict[str, str]:
    """Parse a dpkg status file into {package: version} for installed packages only."""
    packages: Dict[str, str] = {}
    current: Dict[str, str] = {}

    def flush():
        if not current:
            return
        name, version = current.get("Package"), current.get("Version")
        status = current.get("Status", "")
        # Status looks like "install ok installed"; anything else is deinstalled
        if name and version and status.split()[-1:] == ["installed"]:
            packages[name] = version

    for line in text.splitlines():
        if not line.strip():
            flush()
            current = {}
            continue
        if line.startswith((" ", "\t")):
            continue  # continuation of the previous field
        if ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    flush()
    return packages


def parse_apk_installed(text: str) -> Dict[str, str]:
    """Parse an apk `installed` database into {package: version}.

    Format is one-letter field prefixes, blocks separated by blank lines:
        P:musl
        V:1.2.4-r2
    """
    packages: Dict[str, str] = {}
    name: Optional[str] = None
    for line in text.splitlines():
        if not line:
            name = None
            continue
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:") and name:
            packages[name] = line[2:].strip()
    return packages


def detect_format(flat: Dict[str, dict]) -> Optional[str]:
    """Which package database the flattened image carries (if any)."""
    if DPKG_STATUS in flat:
        return "dpkg"
    if APK_INSTALLED in flat:
        return "apk"
    return None


def inventory_from_merge(merge_dir: Path, flat: Dict[str, dict]) -> Tuple[Dict[str, str], Optional[str]]:
    """Read the package inventory out of a flattened image.

    Returns ({name: version}, format). format is None when the image carries a
    package database this tool does not parse (see module docstring).
    """
    fmt = detect_format(flat)
    if fmt is None:
        return {}, None
    rel = DPKG_STATUS if fmt == "dpkg" else APK_INSTALLED
    path = merge_dir / rel.lstrip("/")
    if not path.exists():
        return {}, None
    text = path.read_text(errors="replace")
    return (parse_dpkg_status(text) if fmt == "dpkg" else parse_apk_installed(text)), fmt


def diff_packages(old: Dict[str, str], new: Dict[str, str]) -> Dict[str, Any]:
    """Added / removed / upgraded packages between two inventories."""
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    upgraded = sorted(
        ((name, old[name], new[name]) for name in set(old) & set(new) if old[name] != new[name]),
        key=lambda t: t[0],
    )
    return {
        "added": added,
        "removed": removed,
        "upgraded": [{"package": n, "from": o, "to": v} for n, o, v in upgraded],
        "counts": {"added": len(added), "removed": len(removed), "upgraded": len(upgraded)},
    }


def summarise(delta: Dict[str, Any], fmt: Optional[str]) -> str:
    """One-line human summary for the diff report."""
    if fmt is None:
        return "Package inventory: unavailable (no dpkg/apk database in either image)"
    counts = delta["counts"]
    return (f"Packages ({fmt}): +{counts['added']} -{counts['removed']} "
            f"^ {counts['upgraded']}")
