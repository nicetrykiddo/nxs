from __future__ import annotations

import re

from rich.console import Console
from rich.panel import Panel

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


def print_probe_summary(target: str, reachable: list[str], total: int, domain: str | None = None) -> None:
    names = ", ".join(p.upper() for p in reachable) if reachable else "none"
    domain_str = f" · [dim]{domain}[/dim]" if domain else ""
    console.print(
        f"\n[dim]nxs v{__version__}[/dim]"
        f" [bold]{target}[/bold]{domain_str}"
        f" · [dim]probe: {len(reachable)}/{total} ports open[/dim]"
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
    details = []
    if not result.records:
        return details

    proto = result.protocol.lower()
    raw = "\n".join(r.output for r in result.records)

    if proto == "smb" and result.level in {"READ", "WRITE", "ADMIN"}:
        for line in raw.splitlines():
            if "READ" in line or "WRITE" in line:
                details.append(clean_nxc_line(line))
    elif proto == "ldap" and result.level in {"READ", "WRITE"}:
        capture = False
        for line in raw.splitlines():
            if "Enumerated" in line:
                capture = True
                details.append(clean_nxc_line(line))
                continue
            if capture and line.strip() and not ("[+]" in line or "[-]" in line or "[*]" in line):
                details.append(clean_nxc_line(line))
    elif proto in {"ssh", "winrm", "wmi"} and result.level == "EXEC":
        capture = False
        for line in raw.splitlines():
            if "[+]" in line:
                capture = True
                continue
            if capture and line.strip() and not line.startswith("[-]") and not line.startswith("[*]"):
                details.append(clean_nxc_line(line))

    return details


def print_result_event(result: ProtocolResult, verbose: bool = False) -> None:
    style = LEVEL_STYLE.get(result.level, "white")
    mark = LEVEL_MARK.get(result.level, "[*]")

    console.print(
        f"  [{style}]{mark}[/{style}] [blue]{result.protocol.upper():<6}[/blue] "
        f"[{style}]{result.level:<8}[/{style}] "
        f"{result.proof}"
    )

    if verbose and result.level not in {"NO", "UNCLEAR"}:
        details = extract_verbose_details(result)
        for detail in details:
            console.print(f"      [dim]↳ {detail}[/dim]")


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