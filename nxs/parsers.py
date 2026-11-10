"""Parsers for NetExec's human-oriented output.

Only interpret structured rows after their corresponding NXC table header.
Never infer access from a banner or an unrelated status message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

NXC_PREFIX = re.compile(r"^[A-Z][A-Z0-9_]*\s+\S+\s+\d+\s+\S+\s+(.*)$")
PERMISSIONS = {"READ", "WRITE", "READ,WRITE", "WRITE,READ"}


@dataclass(frozen=True)
class ShareAccess:
    name: str
    permissions: frozenset[str]
    remark: str = ""

    @property
    def display_permissions(self) -> str:
        return "+".join(p for p in ("READ", "WRITE") if p in self.permissions) or "—"


def clean_nxc_line(line: str) -> str:
    line = line.rstrip("\x00\r\n")
    match = NXC_PREFIX.match(line)
    return match.group(1).strip() if match else line.strip()


def parse_smb_shares(output: str) -> list[ShareAccess]:
    """Extract all SMB share rows, including names containing spaces or 'Share'.

    An enumerated share with no listed permissions is *not* a readable share.
    """
    started = False
    rows: list[ShareAccess] = []
    for raw in output.splitlines():
        line = clean_nxc_line(raw)
        if "Enumerated shares" in line:
            started = True
            continue
        if not started:
            continue
        if not line or line.startswith(("[", "SMB ")):
            continue
        columns = re.split(r"\s{2,}", line, maxsplit=2)
        name = columns[0].strip()
        if not name or re.fullmatch(r"-+", name):
            continue
        if name == "Share" and len(columns) > 1 and columns[1] == "Permissions":
            continue
        if len(columns) < 2:
            continue
        perms = columns[1] if columns[1] in PERMISSIONS else ""
        remark = (columns[2] if len(columns) > 2 else "") if perms else " ".join(columns[1:])
        if not re.fullmatch(r"[^\\/\x00-\x1f]+", name):
            continue
        rows.append(ShareAccess(name, frozenset(perms.split(",")) if perms else frozenset(), remark))
    return rows


def smb_metadata(output: str) -> dict[str, str]:
    """Return metadata exactly as NXC advertised it, without interpreting policy."""
    for raw in output.splitlines():
        line = clean_nxc_line(raw)
        if not line.startswith("[*] ") or "(name:" not in line:
            continue
        fields = {}
        for key in ("name", "domain", "signing", "SMBv1", "Null Auth"):
            match = re.search(r"\(" + re.escape(key) + r":([^)]*)\)", line)
            if match:
                fields[key] = match.group(1)
        return fields
    return {}
