from __future__ import annotations

import re

from rich.console import Console
from rich.panel import Panel
from rich.markup import escape

from . import __version__
from .models import Credential, ProtocolResult
from .parsers import clean_nxc_line, parse_smb_shares, smb_metadata
from .runner import record_dict

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
    "SHELL": "green",
    "READ": "green",
    "WRITE": "green",
    "EXEC": "bold green",
    "ADMIN": "bold magenta",
}

LEVEL_MARK = {
    "NO": "[-]",
    "UNCLEAR": "[?]",
    "AUTH": "[*]",
    "SHELL": "[+]",
    "READ": "[+]",
    "WRITE": "[+]",
    "EXEC": "[+]",
    "ADMIN": "[!]",
}


def cred_label(cred: Credential) -> str:
    """Display the exact supplied identity and secret."""
    who = cred.user or "<anonymous>"
    if cred.ccache_file:
        return f"{who} [{cred.ccache_file}]"
    if cred.ntlm_hash is not None:
        return f"{who}:{cred.ntlm_hash}"
    if cred.password is not None:
        return f"{who}:{cred.password}"
    return who


def print_scan_header(target: str, cred: Credential, domain: str | None, protocol_count: int) -> None:
    identity = cred_label(cred)
    if domain:
        identity += f"@{domain}"
    console.print(
        f"\n[bold]{escape(target)}[/bold] · {escape(identity)}"
        f" · [dim]{protocol_count} protocols[/dim]\n",
        highlight=False,
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
        protos = port_map.get(t, [])
        names = ", ".join(p.upper() for p in protos) if protos else "none"
        domain_str = f" · [dim]{domain}[/dim]" if domain else ""
        console.print(
            f"\n[dim]nxs v{__version__}[/dim]"
            f" [bold]{t}[/bold]{domain_str}"
            f" · [dim]probe: {len(protos)}/{total} ports open[/dim]"
            f" · [cyan]{names}[/cyan]\n"
        )


def print_anchor_result(cred: Credential, anchor: str, ok: bool, proof: str) -> None:
    label = escape(cred_label(cred))
    if ok:
        console.print(
            f"  [green][+][/green] [bold]{label}[/bold]"
            f" · [blue]{anchor.upper()}[/blue] [green]valid[/green]"
            f" — {escape(proof)}",
            highlight=False,
        )
    else:
        console.print(
            f"  [red][-][/red] [dim]{label}[/dim]"
            f" · [blue]{anchor.upper()}[/blue] [red]failed[/red]"
            f" — {escape(proof)}",
            highlight=False,
        )




def extract_verbose_details(result: ProtocolResult) -> list[str]:
    details: list[str] = []
    if not result.records:
        return details

    proto = result.protocol.lower()

    def add(line: str) -> None:
        if line and line not in details:
            details.append(line)

    # Authentication and service metadata are useful even when no capability was
    # confirmed. Display each item once rather than repeating it for every NXC call.
    for record in result.records:
        for line in record_dict(record)["output"].splitlines():
            cleaned = clean_nxc_line(line).rstrip("\x00")
            if cleaned.startswith(("[*] Windows", "[*] Linux", "[+]")):
                add(cleaned)

    if proto == "smb":
        for record in result.records:
            if "--shares" in record.command and "Enumerated shares" in record.output:
                for share in parse_smb_shares(record_dict(record)["output"]):
                    add(f"{share.name:<24} {share.display_permissions:<10} {share.remark}".rstrip())

            elif "--dir" in record.command:
                share = record.command[record.command.index("--share") + 1] if "--share" in record.command else "?"
                add(f"{share}/ (root only)")
                found = False
                for line in record_dict(record)["output"].splitlines():
                    cleaned = clean_nxc_line(line).rstrip("\x00")
                    # NetExec --dir returns: permissions, size, modified date, name.
                    match = re.match(
                        r"^([df][rw-]{3})\s+(\d+)\s+"
                        r"([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+"
                        r"\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$",
                        cleaned,
                    )
                    if not match:
                        continue
                    flags, size, stamp, name = match.groups()
                    name = name.strip()
                    if name in {".", ".."}:
                        continue
                    found = True
                    kind = "dir" if flags.startswith("d") else "file"
                    display_name = name + ("/" if kind == "dir" else "")
                    from datetime import datetime
                    try:
                        modified = datetime.strptime(stamp, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d")
                    except ValueError:
                        modified = stamp
                    detail = f"  {display_name}  · {kind}"
                    if kind == "file":
                        detail += f" · {int(size):,} B"
                    add(f"{detail} · {modified}")
                if not found:
                    add("  no parseable listing (empty, denied, or unsupported output)")

            elif "--users" in record.command:
                add("SAMR user enumeration (SMB)")
                for line in record_dict(record)["output"].splitlines():
                    cleaned = clean_nxc_line(line).rstrip("\x00")
                    if cleaned and not cleaned.startswith(("[*] Windows", "[+]")):
                        add(cleaned)

    elif proto == "ldap":
        for record in result.records:
            if "--users" not in record.command:
                continue
            in_user_table = False
            for line in record_dict(record)["output"].splitlines():
                cleaned = clean_nxc_line(line).rstrip("\x00")
                if re.search(r"\bEnumerated\s+\d+\s+domain users\b", cleaned, re.I):
                    in_user_table = True
                    # The summary is already shown in the main result.
                    continue
                if in_user_table:
                    if cleaned.startswith(("[*]", "[+]", "[-]", "[!]")):
                        in_user_table = False
                    elif cleaned:
                        # Do not truncate LDAP descriptions, columns, or usernames.
                        add(cleaned)

    elif proto in {"ssh", "winrm", "wmi"}:
        for record in result.records:
            if "-x" not in record.command and "-X" not in record.command:
                continue
            for line in record_dict(record)["output"].splitlines():
                cleaned = clean_nxc_line(line).rstrip("\x00")
                if cleaned and not cleaned.startswith(("[*]", "[+]", "[-]")):
                    add(cleaned)

    # Never shorten an original NXC error. This applies to NO and UNCLEAR too.
    for record in result.records:
        for line in record_dict(record)["output"].splitlines():
            if "[-]" in line:
                add(clean_nxc_line(line).rstrip("\x00"))

    return details


def print_result_event(result: ProtocolResult, verbose: bool = False) -> None:
    style = LEVEL_STYLE.get(result.level, "white")
    mark = LEVEL_MARK.get(result.level, "[*]")

    console.print(
        f"  [{style}]{mark}[/{style}] [blue]{result.protocol.upper():<6}[/blue] "
        f"[{style}]{result.level:<8}[/{style}] "
        f"{escape(result.proof)}",
        highlight=False,
    )

    if result.protocol.lower() == "smb":
        for record in result.records:
            meta = smb_metadata(record.output)
            if meta:
                summary = " · ".join(f"{key}={meta[key]}" for key in
                                     ("name", "domain", "signing", "SMBv1", "Null Auth") if key in meta)
                console.print(f"      [dim]↳ {escape(summary)}[/dim]", highlight=False)
                break

    if verbose:
        details = extract_verbose_details(result)
        for detail in details:
            console.print(f"      [dim]↳ {escape(detail)}[/dim]", highlight=False)


def print_results(
    target: str,
    user: str | Credential,
    results: list[ProtocolResult],
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    if quiet:
        identity = cred_label(user) if isinstance(user, Credential) else user
        for result in results:
            if result.level not in {"NO", "UNCLEAR"}:
                print(f"{target} {identity} {result.protocol.upper()} {result.level} {result.proof}")
        return

    console.print(f"\n  [bold]{escape(target)}[/bold]  {escape(cred_label(user) if isinstance(user, Credential) else user)}\n", highlight=False)

    for result in results:
        print_result_event(result, verbose=verbose)

def print_discovery_results(
    target: str,
    results_by_identity: dict[str, list[ProtocolResult]],
    *,
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    """Summarize empty-credential and guest checks together, without conflating access."""
    indexed = {
        identity: {result.protocol: result for result in results}
        for identity, results in results_by_identity.items()
    }
    protocols = list(dict.fromkeys(
        result.protocol
        for results in results_by_identity.values()
        for result in results
    ))
    rank = {"NO": 0, "UNCLEAR": 1, "AUTH": 2, "READ": 3,
            "WRITE": 4, "SHELL": 5, "EXEC": 6, "ADMIN": 7}

    if not quiet:
        console.print(
            f"\n[bold]{escape(target)}[/bold] · [dim]null session + guest discovery[/dim]\n",
            highlight=False,
        )
        if not protocols:
            console.print("  [dim]No reachable protocols[/dim]")

    for protocol in protocols:
        candidates = [
            (identity, indexed[identity][protocol])
            for identity in ("null", "guest")
            if protocol in indexed.get(identity, {})
        ]
        if not candidates:
            continue
        # Prefer the null attempt on a tie: it needs fewer privileges.
        identity, best = max(candidates, key=lambda pair: rank.get(pair[1].level, -1))
        equivalent = len(candidates) == 2 and all(
            item.level == best.level and item.proof == best.proof
            for _, item in candidates
        )
        source = "null + guest" if equivalent else identity

        if quiet:
            if best.level not in {"NO", "UNCLEAR"}:
                print(f"{target} {protocol.upper()} {best.level} [{source}] {best.proof}")
            continue

        shown = ProtocolResult(
            protocol=best.protocol, ok=best.ok, level=best.level,
            proof=f"{best.proof} · {source}", mode=best.mode, records=best.records,
        )
        print_result_event(shown, verbose=verbose)
        if not equivalent:
            for other_identity, other in candidates:
                if other_identity == identity:
                    continue
                console.print(
                    f"      [dim]↳ {other_identity}: {other.level} · {escape(other.proof)}[/dim]",
                    highlight=False,
                )
