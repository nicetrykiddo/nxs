"""Parsers for NetExec's human-oriented output.

Only interpret structured rows after their corresponding NXC table header.
Never infer access from a banner or an unrelated status message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

NXC_PREFIX = re.compile(r"^[A-Z][A-Z0-9_-]*\s+\S+\s+\d+\s+\S+\s+(.*)$")
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
    """Parse permission-bearing share rows without assuming fixed column widths."""
    announced = False
    in_table = False
    rows: list[ShareAccess] = []
    for raw in output.splitlines():
        line = clean_nxc_line(raw)
        if "Enumerated shares" in line:
            announced = True
            in_table = False
            continue
        if announced and re.match(r"^Share\s{2,}Permissions\b", line):
            in_table = True
            continue
        if not in_table or not line or line.startswith(("[", "SMB ")):
            continue
        if re.fullmatch(r"[-\s]+", line):
            continue

        match = re.match(
            r"^(.*\S)\s{2,}(READ,WRITE|WRITE,READ|READ|WRITE)(?:\s{2,}(.*))?$",
            line,
        )
        if match:
            name, perms, remark = match.groups()
        else:
            parts = re.split(r"\s{2,}", line, maxsplit=1)
            name, perms, remark = parts[0], "", parts[1] if len(parts) > 1 else ""

        if name and re.fullmatch(r"[^\\/\x00-\x1f]+", name):
            rows.append(ShareAccess(name, frozenset(perms.split(",")) if perms else frozenset(), remark or ""))
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
