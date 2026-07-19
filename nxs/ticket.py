from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

import typer

_err = Console(stderr=True)

CCACHE_GLOBS = ["*.ccache", "*.krb5cc", "*krb5cc"]


@dataclass
class TicketInfo:
    principal: str
    realm: str
    path: Path
    expires: datetime | None
    expired: bool


def _parse_impacket(path: Path) -> TicketInfo:
    from impacket.krb5.ccache import CCache

    ccache = CCache.loadFile(str(path))
    principal = ccache.principal

    realm = principal.realm["data"].decode()
    components = [c["data"].decode() for c in principal.components]
    user = "/".join(components) if components else "unknown"

    max_end = 0
    for cred in ccache.credentials:
        end = cred["time"]["endtime"]
        if end > max_end:
            max_end = end

    expires = datetime.fromtimestamp(max_end, tz=timezone.utc) if max_end else None
    expired = expires is not None and expires < datetime.now(tz=timezone.utc)

    return TicketInfo(principal=user, realm=realm, path=path, expires=expires, expired=expired)


def _parse_klist(path: Path) -> TicketInfo:
    result = subprocess.run(
        ["klist", "-c", str(path)],
        capture_output=True, text=True, timeout=5,
    )
    output = result.stdout + result.stderr

    principal = "unknown"
    realm = ""
    expires = None

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Default principal:"):
            full = line.split(":", 1)[1].strip()
            if "@" in full:
                principal, realm = full.rsplit("@", 1)
            else:
                principal = full

        match = re.match(r"^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", line)
        if match:
            try:
                dt = datetime.strptime(match.group(1), "%m/%d/%Y %H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
                if expires is None or dt > expires:
                    expires = dt
            except ValueError:
                pass

    if principal == "unknown":
        raise ValueError("klist did not return principal")

    expired = expires is not None and expires < datetime.now(tz=timezone.utc)
    return TicketInfo(principal=principal, realm=realm, path=path, expires=expires, expired=expired)


def _parse_binary(path: Path) -> TicketInfo:
    data = path.read_bytes()
    if len(data) < 10:
        raise ValueError("file too small for ccache")

    off = 0
    version = struct.unpack(">H", data[off:off + 2])[0]
    off += 2

    if version == 0x0504:
        hdr_len = struct.unpack(">H", data[off:off + 2])[0]
        off += 2 + hdr_len
    elif version in (0x0501, 0x0502, 0x0503):
        pass
    else:
        raise ValueError(f"unknown ccache version: {version:#06x}")

    # default principal
    _ptype = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    num_components = struct.unpack(">I", data[off:off + 4])[0]
    off += 4

    realm_len = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    realm = data[off:off + realm_len].decode("utf-8", errors="replace")
    off += realm_len

    components = []
    for _ in range(num_components):
        comp_len = struct.unpack(">I", data[off:off + 4])[0]
        off += 4
        components.append(data[off:off + comp_len].decode("utf-8", errors="replace"))
        off += comp_len

    user = "/".join(components) if components else "unknown"
    return TicketInfo(principal=user, realm=realm, path=path, expires=None, expired=False)


def parse_ccache(path: Path) -> TicketInfo:
    # try impacket
    try:
        return _parse_impacket(path)
    except ImportError:
        pass
    except Exception:
        pass

    # try klist
    try:
        return _parse_klist(path)
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass

    # binary fallback
    try:
        return _parse_binary(path)
    except Exception as e:
        raise typer.BadParameter(
            f"cannot parse ticket {path.name}: {e}. "
            f"Install impacket or klist for better support."
        ) from e


def discover_tickets(path: str) -> list[TicketInfo]:
    p = Path(path)

    if p.is_file():
        info = parse_ccache(p)
        if info.expired:
            _err.print(f"  [yellow][!][/yellow] [dim]{p.name}[/dim] — ticket expired ({info.expires})")
            raise typer.BadParameter(f"ticket expired: {p.name}")
        return [info]

    if p.is_dir():
        files: set[Path] = set()
        for glob in CCACHE_GLOBS:
            files.update(p.glob(glob))

        if not files:
            raise typer.BadParameter(f"no ccache/krb5cc files in {p}")

        valid = []
        for f in sorted(files):
            try:
                info = parse_ccache(f)
            except typer.BadParameter as e:
                _err.print(f"  [yellow][!][/yellow] [dim]{f.name}[/dim] — {e}")
                continue

            if info.expired:
                _err.print(f"  [yellow][!][/yellow] [dim]{f.name}[/dim] — ticket expired ({info.expires})")
                continue

            valid.append(info)

        if not valid:
            raise typer.BadParameter(f"no valid tickets in {p}")
        return valid

    raise typer.BadParameter(f"ticket path not found: {path}")
