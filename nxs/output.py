from __future__ import annotations

import re

from rich.console import Console
from rich.panel import Panel
from rich.markup import escape

from . import __version__
from .models import Credential, ProtocolResult

console = Console()

def print_banner() -> None:
    banner = (
        "[bold cyan]nxs[/bold cyan] - [dim]Credential capability mapping for NetExec[/dim]\n\n"
        "[white]Stop guessing what your creds can do. Blasts your credentials\n"
        "across all protocols and maps out your exact access level.[/white]\n\n"
        "[blue]Usage:[/blue] [bold]nxs[/bold] [dim]<target> -u <user> -p <pass>[/dim]\n"
        "[blue]Help:[/blue]  [bold]nxs[/bold] [dim]--help[/dim]"
    )
    console.print(
        Panel(
            banner,
            title=f"nxs v{__version__}",
            border_style="cyan",
            expand=False,
        )
    )

LEVEL_STYLE = {
    "NO": "red",
    "UNCLEAR": "yellow",
    "AUTH": "blue",
    "READ": "green",
    "WRITE": "green",
    "EXEC": "bold green",
    "ADMIN": "bold magenta",
}

LEVEL_MARK = {
    "NO": "[-]",
    "UNCLEAR": "[?]",
    "AUTH": "[*]",
    "READ": "[+]",
    "WRITE": "[+]",
    "EXEC": "[+]",
    "ADMIN": "[!]",
}


def cred_label(cred: Credential) -> str:
    """Format credential for display: user:secret."""
    if cred.ccache_file:
        return f"{cred.user} [ticket]"
    if cred.ntlm_hash:
        return f"{cred.user}:{cred.ntlm_hash}"
    if cred.password:
        return f"{cred.user}:{cred.password}"
    return cred.user


def print_scan_header(target: str, cred: Credential, domain: str | None, protocol_count: int) -> None:
    identity = cred_label(cred)
    if domain:
        identity += f"@{domain}"
    console.print(
        f"\n[dim]nxs v{__version__}[/dim]"
        f" [bold]{target}[/bold] · {identity}"
        f" · [dim]{protocol_count} protocols[/dim]\n"
    )


def print_probe_summary(raw_target: str, targets: list[str], port_map: dict[str, list[str]], all_protocols: list[str], domain: str | None = None, verbose: bool = False) -> None:
    multi = len(targets) > 1
    total = len(all_protocols)
    reachable_targets = [t for t in targets if port_map.get(t)]

    if multi:
        domain_str = f" · [dim]{domain}[/dim]" if domain else ""
        console.print(
            f"\n[dim]nxs v{__version__}[/dim]"
            f" [bold]{raw_target}[/bold] [dim]({len(targets)} targets)[/dim]{domain_str}"
            f" · [dim]probe: {len(reachable_targets)}/{len(targets)} reachable[/dim]\n"
        )
        for t in targets:
            protos = port_map.get(t, [])
            if protos:
                names = ", ".join(p.upper() for p in protos)
                console.print(f"  [bold]{t}[/bold]  [dim]{len(protos)}/{total}[/dim]  [cyan]{names}[/cyan]")
            elif verbose:
                console.print(f"  [dim]{t}  0/{total}[/dim]")
        console.print()
    else:
        t = targets[0]
        protos = port_map.get(t, all_protocols)
        names = ", ".join(p.upper() for p in protos) if protos else "none"
        domain_str = f" · [dim]{domain}[/dim]" if domain else ""
        console.print(
            f"\n[dim]nxs v{__version__}[/dim]"
            f" [bold]{t}[/bold]{domain_str}"
            f" · [dim]probe: {len(protos)}/{total} ports open[/dim]"
            f" · [cyan]{names}[/cyan]\n"
        )


def print_anchor_result(cred: Credential, anchor: str, ok: bool, proof: str) -> None:
    label = cred_label(cred)
    if ok:
        console.print(
            f"  [green][+][/green] [bold]{label}[/bold]"
            f" · [blue]{anchor.upper()}[/blue] [green]valid[/green]"
            f" — {proof}"
        )
    else:
        console.print(
            f"  [red][-][/red] [dim]{label}[/dim]"
            f" · [blue]{anchor.upper()}[/blue] [red]failed[/red]"
            f" — {proof}"
        )


def clean_nxc_line(line: str) -> str:
    match = re.match(r"^[A-Za-z]+\s+[0-9a-zA-Z\.\\:\-]+\s+\d+\s+\S+\s+(.*)", line)
    return match.group(1).strip() if match else line.strip()


def extract_verbose_details(result: ProtocolResult) -> list[str]:
    details: list[str] = []
    if not result.records:
        return details

    proto = result.protocol.lower()
    if proto == "smb":
        for record in result.records:
            if "--shares" in record.command and "Enumerated shares" in record.output:
                started = False
                for line in record.output.splitlines():
                    cleaned = clean_nxc_line(line)
                    if "Enumerated shares" in cleaned:
                        started = True
                        continue
                    if not started or not cleaned or cleaned.startswith(("Share", "---", "[", "SMB ")):
                        continue
                    parts = cleaned.split(None, 1)
                    if not parts:
                        continue
                    share = parts[0]
                    if not re.fullmatch(r"[A-Za-z0-9._$-]+", share):
                        continue
                    tail = parts[1] if len(parts) > 1 else ""
                    perm = re.match(r"^(READ,WRITE|WRITE,READ|READ|WRITE)(?:\s|$)", tail)
                    label = perm.group(1) if perm else "—"
                    details.append(f"{share:<16} {label}")
            elif "--dir" in record.command:
                share = record.command[record.command.index("--share") + 1] if "--share" in record.command else "?"
                details.append(f"{share}/ (root only)")
                shown = 0
                for line in record.output.splitlines():
                    cleaned = clean_nxc_line(line).rstrip("\x00")
                    if not cleaned or cleaned.startswith(("[*]", "[+]", "[-]")):
                        continue
                    if shown >= 50:
                        details.append("  ... truncated after 50 entries")
                        break
                    details.append("  " + cleaned)
                    shown += 1
    elif proto == "ldap":
        for record in result.records:
            if "--users" not in record.command:
                continue
            for line in record.output.splitlines():
                cleaned = clean_nxc_line(line)
                if "Enumerated" in cleaned:
                    details.append(cleaned)
    elif proto in {"ssh", "winrm", "wmi"}:
        for record in result.records:
            if "-x" not in record.command:
                continue
            for line in record.output.splitlines():
                cleaned = clean_nxc_line(line).rstrip("\x00")
                if cleaned and not cleaned.startswith(("[*]", "[+]", "[-]")):
                    details.append(cleaned)

    # Include the full source error even when the capability is NO or UNCLEAR.
    for record in result.records:
        for line in record.output.splitlines():
            if "[-]" in line:
                cleaned = clean_nxc_line(line).rstrip("\x00")
                if cleaned and cleaned not in details:
                    details.append(cleaned)

    return details


def print_result_event(result: ProtocolResult, verbose: bool = False) -> None:
    style = LEVEL_STYLE.get(result.level, "white")
    mark = LEVEL_MARK.get(result.level, "[*]")

    console.print(
        f"  [{style}]{mark}[/{style}] [blue]{result.protocol.upper():<6}[/blue] "
        f"[{style}]{result.level:<8}[/{style}] "
        f"{result.proof}"
    )

    if verbose:
        details = extract_verbose_details(result)
        for detail in details:
            console.print(f"      [dim]↳ {escape(detail)}[/dim]")


def print_results(
    target: str,
    user: str,
    results: list[ProtocolResult],
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    if quiet:
        for result in results:
            if result.level not in {"NO", "UNCLEAR"}:
                print(f"{result.protocol.upper()} {result.level} {result.proof}")
        return

    console.print(f"\n  [bold]{target}[/bold]  {user}\n")

    for result in results:
        print_result_event(result, verbose=verbose)