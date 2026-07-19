from __future__ import annotations

import getpass
import itertools
import json
import re
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .models import Credential
from .output import (
    console,
    print_anchor_result,
    print_probe_summary,
    print_result_event,
    print_results,
    print_scan_header,
)
from .profiles import ANCHOR_PRIORITY, SUPPORTED_PROTOCOLS
from .runner import kill_all_procs, probe_ports, save_records, test_protocol
from .ticket import discover_tickets

class NxsTyper(typer.Typer):
    def __call__(self, *args, **kwargs):
        if len(sys.argv) == 1:
            from .output import print_banner
            print_banner()
            sys.exit(0)
        return super().__call__(*args, **kwargs)

app = NxsTyper(
    no_args_is_help=False,
    add_completion=False,
)

_shutdown_event = threading.Event()


def _sigint_handler(signum, frame):
    _shutdown_event.set()
    kill_all_procs()
    console.print("\n  [dim]interrupted[/dim]")
    sys.exit(130)

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
LM_NT_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")

PROTOCOL_LIST = ",".join(SUPPORTED_PROTOCOLS)


def version_callback(value: bool):
    if value:
        typer.echo(f"nxs {__version__}")
        raise typer.Exit()


def read_file_or_value(value: str) -> list[str]:
    path = Path(value)
    if path.is_file():
        lines = [
            line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not lines:
            raise typer.BadParameter(f"file is empty: {value}")
        return lines
    if path.suffix.lower() in {".txt", ".lst", ".list", ".csv", ".tsv", ".conf", ".cfg"}:
        raise typer.BadParameter(f"file not found: {value}")
    return [value]


def normalize_hash(value: str) -> str:
    value = value.strip()

    if HEX32_RE.match(value):
        if value.lower() == EMPTY_LM:
            raise typer.BadParameter(
                "aad3b435... is the empty LM placeholder. "
                "Pass the NT hash instead, or use LM:NT format."
            )
        return value

    if LM_NT_RE.match(value):
        lm_hash, nt_hash = value.split(":", 1)
        if nt_hash.lower() == EMPTY_LM:
            raise typer.BadParameter(
                "the NT half of LM:NT is aad3b435..., which looks wrong. "
                "Pass a real NT hash."
            )
        return f"{lm_hash}:{nt_hash}"

    raise typer.BadParameter("hash must be NT_HASH or LM_HASH:NT_HASH")


def parse_protocols(protocols: Optional[str]) -> list[str]:
    if protocols:
        selected = [p.strip().lower() for p in protocols.split(",") if p.strip()]
    else:
        selected = SUPPORTED_PROTOCOLS[:]

    invalid = [p for p in selected if p not in SUPPORTED_PROTOCOLS]
    if invalid:
        raise typer.BadParameter(
            f"unsupported: {', '.join(invalid)}. "
            f"available: {PROTOCOL_LIST}"
        )

    return selected


def resolve_credentials(
    user: Optional[str],
    password: Optional[str],
    ntlm_hash: Optional[str],
    domain: Optional[str],
    creds_file: Optional[str],
    combo: bool = False,
) -> list[Credential]:
    if creds_file:
        path = Path(creds_file)
        if not path.is_file():
            if not user:
                raise typer.BadParameter(f"File not found: '{creds_file}' (Did you forget the -u/--user flag?)")
            raise typer.BadParameter(f"creds file not found: {creds_file}")

        creds = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise typer.BadParameter(f"bad line in creds file (expected user:secret): {line}")

            u, secret = line.split(":", 1)
            try:
                parsed_hash = normalize_hash(secret)
                creds.append(Credential(user=u, ntlm_hash=parsed_hash, domain=domain))
            except typer.BadParameter:
                creds.append(Credential(user=u, password=secret, domain=domain))
        if not creds:
            raise typer.BadParameter(f"no valid entries in creds file: {creds_file}")
        return creds

    if not user:
        raise typer.BadParameter("Provide either a creds file or -u/--user")

    if password and ntlm_hash:
        raise typer.BadParameter("use either --password or --hash, not both")

    users = read_file_or_value(user)

    if ntlm_hash:
        hashes = read_file_or_value(ntlm_hash)
        if combo:
            return [
                Credential(user=u, ntlm_hash=normalize_hash(h), domain=domain)
                for u, h in itertools.product(users, hashes)
            ]
        if len(hashes) == 1:
            hashes = hashes * len(users)
        elif len(users) == 1:
            users = users * len(hashes)
        elif len(hashes) != len(users):
            raise typer.BadParameter(
                f"-u has {len(users)} entries but -H has {len(hashes)}. "
                f"Use -C/--combo to try all {len(users)}×{len(hashes)} combinations"
            )
        return [
            Credential(user=u, ntlm_hash=normalize_hash(h), domain=domain)
            for u, h in zip(users, hashes)
        ]

    if password:
        passwords = read_file_or_value(password)
        if combo:
            return [
                Credential(user=u, password=p, domain=domain)
                for u, p in itertools.product(users, passwords)
            ]
        if len(passwords) == 1:
            passwords = passwords * len(users)
        elif len(users) == 1:
            users = users * len(passwords)
        elif len(passwords) != len(users):
            raise typer.BadParameter(
                f"-u has {len(users)} entries but -p has {len(passwords)}. "
                f"Use -C/--combo to try all {len(users)}×{len(passwords)} combinations"
            )
        return [
            Credential(user=u, password=p, domain=domain)
            for u, p in zip(users, passwords)
        ]

    if len(users) > 1:
        raise typer.BadParameter("provide -p or -H when using a user file")

    return [Credential(user=users[0], password=getpass.getpass("Password: "), domain=domain)]


def run_check(
    target: str,
    cred: Credential,
    protocols: list[str],
    timeout: int,
    retries: int,
    threads: int,
    local_auth: bool = False,
    try_local: bool = False,
    kerberos: bool = False,
    kdc_host: Optional[str] = None,
    debug: bool = False,
    delay: float = 0.0,
    on_result=None,
):
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                test_protocol, target, protocol, cred, timeout, retries,
                local_auth=local_auth, try_local=try_local,
                kerberos=kerberos, kdc_host=kdc_host,
                debug=debug, delay=delay,
            )
            for protocol in protocols
        ]

        for future in as_completed(futures):
            if _shutdown_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            result = future.result()
            results.append(result)
            if on_result:
                on_result(result)

    order = {proto: idx for idx, proto in enumerate(protocols)}
    return sorted(results, key=lambda r: order.get(r.protocol, 999))


def _make_stream_handler(verbose: bool):
    """Single factory for the on_result streaming callback."""
    def handler(res):
        print_result_event(res, verbose=verbose)
    return handler


@app.command()
def main(
    target: str = typer.Argument(..., help="Target IP, hostname, CIDR, or file"),
    creds_file: Optional[str] = typer.Option(None, "-f", "--file", help="Optional file with user:pass or user:hash lines"),
    user: Optional[str] = typer.Option(None, "-u", "--user", help="Username or file with usernames"),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password or file with passwords"),
    ntlm_hash: Optional[str] = typer.Option(None, "-H", "--hash", help="NTLM hash or file with hashes"),
    ticket: Optional[str] = typer.Option(None, "-T", "--ticket", help="Kerberos ccache file or directory of tickets"),
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain"),
    combo: bool = typer.Option(False, "-C", "--combo", help="Try all user×password combinations"),
    opsec: bool = typer.Option(False, "--opsec", help="Single-threaded, low retry"),
    protocols: Optional[str] = typer.Option(None, "--protocols", help=f"Comma list ({PROTOCOL_LIST})"),
    local_auth: bool = typer.Option(False, "--local-auth", help="Local auth for SMB/WMI"),
    try_local: bool = typer.Option(False, "--try-local", help="Retry with --local-auth on unclear"),
    kerberos: bool = typer.Option(False, "-k", "--kerberos", help="Use Kerberos"),
    kdc_host: Optional[str] = typer.Option(None, "--kdc-host", help="KDC host for Kerberos"),
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
    raw: bool = typer.Option(False, "--raw", help="Include raw nxc output in JSON"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Only print valid protocols"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save raw proof output to directory"),
    timeout: int = typer.Option(30, "--timeout", help="Per-command timeout in seconds"),
    retries: int = typer.Option(1, "--retries", help="Retries for unclear responses"),
    threads: int = typer.Option(5, "-t", "--threads", help="Protocol worker threads"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between retries in seconds"),
    debug: bool = typer.Option(False, "--debug", help="Show underlying nxc commands"),
    verbose: bool = typer.Option(False, "-V", "--verbose", help="Show detailed protocol output"),
    version: bool = typer.Option(False, "-v", "--version", help="Show version", callback=version_callback, is_eager=True),
):
    """nxs — Stop guessing what your creds can do. Blasts your credentials across all protocols and maps out your exact access level."""
    signal.signal(signal.SIGINT, _sigint_handler)

    selected = parse_protocols(protocols)
    if opsec:
        threads = 1
        retries = min(retries, 1)

    # ── Ticket auth ──
    if ticket:
        if password or ntlm_hash or creds_file:
            raise typer.BadParameter("-T/--ticket is mutually exclusive with -p, -H, -f")

        tickets = discover_tickets(ticket)
        kerberos = True

        creds = []
        for info in tickets:
            cred_user = user or info.principal
            cred_domain = domain or info.realm
            creds.append(Credential(
                user=cred_user,
                domain=cred_domain,
                ccache_file=info.path,
            ))
    else:
        creds = resolve_credentials(user, password, ntlm_hash, domain, creds_file, combo=combo)
    stream = not json_out and not quiet
    all_json_rows = []

    if len(creds) > 1:
        # ── Phase 0: port probe ──
        reachable = probe_ports(target, selected)
        if stream:
            print_probe_summary(target, reachable, len(selected), domain)

        if not reachable:
            if stream:
                console.print("[red][-][/red] no reachable ports — nothing to test")
            return

        anchor = next((p for p in ANCHOR_PRIORITY if p in reachable), reachable[0])
        remaining = [p for p in reachable if p != anchor]

        # ── Phase 1: anchor validation ──
        if stream:
            console.print(f"  [dim]anchor: {anchor.upper()} — validating {len(creds)} credentials[/dim]\n")

        valid_creds = []
        all_anchor_results = []
        for cred in creds:
            anchor_result = test_protocol(
                target, anchor, cred, timeout, retries,
                local_auth=local_auth, try_local=try_local,
                kerberos=kerberos, kdc_host=kdc_host,
                debug=debug, delay=delay,
            )
            all_anchor_results.append((cred, anchor_result))
            if stream:
                print_anchor_result(cred, anchor, anchor_result.ok, anchor_result.proof)
            if anchor_result.ok:
                valid_creds.append((cred, anchor_result))

        if not valid_creds:
            if stream:
                console.print(f"\n  [dim]0/{len(creds)} credentials valid — skipping full scan[/dim]\n")
            if json_out:
                for cred, anchor_result in all_anchor_results:
                    all_json_rows.append({
                        "target": target,
                        "user": cred.user,
                        "domain": domain,
                        "results": [anchor_result.public_dict(raw=raw)],
                    })
                typer.echo(json.dumps(all_json_rows if len(all_json_rows) != 1 else all_json_rows[0], indent=2))
            return

        if stream:
            console.print(f"\n  [dim]{len(valid_creds)}/{len(creds)} valid — scanning {len(remaining)} remaining protocols[/dim]")

        # ── Phase 2: full scan for valid creds ──
        for cred, anchor_result in valid_creds:
            if stream:
                print_scan_header(target, cred, domain, len(reachable))
                print_result_event(anchor_result, verbose=verbose)

            extra_results = run_check(
                target, cred, remaining, timeout, retries, threads,
                local_auth=local_auth, try_local=try_local,
                kerberos=kerberos, kdc_host=kdc_host,
                debug=debug, delay=delay,
                on_result=_make_stream_handler(verbose) if stream else None,
            ) if remaining else []

            all_results = [anchor_result] + extra_results

            if save:
                for result in all_results:
                    save_records(save, target, cred.user, result)

            if json_out:
                all_json_rows.append({
                    "target": target,
                    "user": cred.user,
                    "domain": domain,
                    "results": [r.public_dict(raw=raw) for r in all_results],
                })
            elif not stream:
                print_results(target, cred.user, all_results, quiet=quiet, verbose=verbose)

    else:
        # ── Single credential: full scan ──
        cred = creds[0]
        if stream:
            print_scan_header(target, cred, domain, len(selected))

        results = run_check(
            target, cred, selected, timeout, retries, threads,
            local_auth=local_auth, try_local=try_local,
            kerberos=kerberos, kdc_host=kdc_host,
            debug=debug, delay=delay,
            on_result=_make_stream_handler(verbose) if stream else None,
        )

        if save:
            for result in results:
                save_records(save, target, cred.user, result)

        if json_out:
            all_json_rows.append({
                "target": target,
                "user": cred.user,
                "domain": domain,
                "results": [r.public_dict(raw=raw) for r in results],
            })
        elif not stream:
            print_results(target, cred.user, results, quiet=quiet, verbose=verbose)

    if json_out:
        typer.echo(json.dumps(all_json_rows[0] if len(all_json_rows) == 1 else all_json_rows, indent=2))


if __name__ == "__main__":
    app()