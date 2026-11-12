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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from typing import Optional

import typer

from . import __version__
from .models import Credential
from .output import (
    console,
    print_anchor_result,
    print_probe_summary,
    print_discovery_results,
    print_result_event,
    print_results,
    print_scan_header,
)
from .profiles import ANCHOR_PRIORITY, SUPPORTED_PROTOCOLS
from .runner import PortProbeError, configure_pacing, get_remote_time, kill_all_procs, probe_ports_per_target, resolve_targets, save_records, target_uses_ipv6, test_protocol, verify_credential
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
        seen = set()
        selected = []
        for p in protocols.split(","):
            p_clean = p.strip().lower()
            if p_clean and p_clean not in seen:
                seen.add(p_clean)
                selected.append(p_clean)
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
            if user is None:
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

    if user is None:
        if password is not None or ntlm_hash is not None:
            raise typer.BadParameter("provide -u/--user when passing a password or hash")
        # No credentials is a deliberate anonymous/guest SMB discovery path.
        return [Credential(user="", password="", domain=domain),
                Credential(user="guest", password="", domain=domain)]

    if password is not None and ntlm_hash is not None:
        raise typer.BadParameter("use either --password or --hash, not both")

    users = read_file_or_value(user)

    if ntlm_hash is not None:
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

    if password is not None:
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


def _probe_targets(targets: list[str], protocols: list[str], ipv6_targets: set[str], opsec: bool) -> dict[str, list[str]]:
    if not opsec:
        return probe_ports_per_target(targets, protocols, ipv6_targets=ipv6_targets)
    result = {}
    for target in targets:
        result.update(probe_ports_per_target(
            [target], protocols,
            ipv6_targets={target} if target in ipv6_targets else set(),
            opsec=True,
        ))
    return result


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
    remote_time: Optional[str] = None,
    ipv6: bool = False,
    opsec: bool = False,
    list_files: bool = False,
    verify_exec: bool = True,
    enum_users: bool = False,
):
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                test_protocol, target, protocol, cred, timeout, retries,
                local_auth=local_auth, try_local=try_local,
                kerberos=kerberos, kdc_host=kdc_host,
                debug=debug, delay=delay, remote_time=remote_time,
                ipv6=ipv6, opsec=opsec, list_files=list_files,
                verify_exec=verify_exec, enum_users=enum_users,
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
    target: str = typer.Argument(..., help="Target IP, hostname, CIDR, or file. No credentials: anonymous + guest discovery"),
    creds_file: Optional[str] = typer.Option(None, "-f", "--file", help="Optional file with user:pass or user:hash lines"),
    user: Optional[str] = typer.Option(None, "-u", "--user", help="Username or file with usernames"),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password or file with passwords"),
    ntlm_hash: Optional[str] = typer.Option(None, "-H", "--hash", help="NTLM hash or file with hashes"),
    ticket: Optional[str] = typer.Option(None, "-T", "--ticket", help="Kerberos ccache file or directory of tickets"),
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain"),
    combo: bool = typer.Option(False, "-C", "--combo", help="Try all user×password combinations"),
    auth_gate: bool = typer.Option(True, "--auth-gate/--no-auth-gate", help="Verify each credential before capability scans (default: on)"),
    opsec: bool = typer.Option(False, "--opsec", help="Sequential paced auth checks; skips automatic capability probes"),
    list_files: bool = typer.Option(False, "--list-files", help="List root entries of readable SMB shares, no recursion"),
    verify_exec: bool = typer.Option(True, "--verify-exec/--no-verify-exec", help="Verify WinRM command execution (default: on; disabled in --opsec)"),
    enum_users: bool = typer.Option(False, "--enum-users", help="Attempt SAMR user enumeration over authenticated SMB (not WMI)"),
    null_session: bool = typer.Option(False, "--null-session", help="Test only empty username/password (no guest fallback)"),
    protocols: Optional[str] = typer.Option(None, "--protocols", help=f"Comma list ({PROTOCOL_LIST})"),
    local_auth: bool = typer.Option(False, "--local-auth", help="Local auth for SMB/WMI"),
    try_local: bool = typer.Option(False, "--try-local", help="Retry with --local-auth on unclear"),
    kerberos: bool = typer.Option(False, "-k", "--kerberos", help="Use Kerberos"),
    ipv6: bool = typer.Option(False, "-6", "--ipv6", help="Force IPv6 (auto-detected for IPv6-only hosts)"),
    kdc_host: Optional[str] = typer.Option(None, "--kdc-host", help="KDC host for Kerberos"),
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
    raw: bool = typer.Option(False, "--raw", help="Include raw nxc output in JSON"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Only print valid protocols"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save raw proof output to directory"),
    timeout: int = typer.Option(60, "--timeout", help="Per-command timeout in seconds"),
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
        retries = 0
        delay = max(delay, 1.5)
    configure_pacing(delay)

    # ── Ticket auth ──
    if null_session and (user is not None or password is not None or ntlm_hash is not None
                         or creds_file is not None or ticket is not None or kerberos):
        raise typer.BadParameter("--null-session cannot be combined with credentials, tickets, or Kerberos")
    discovery_mode = (not null_session and not ticket and not kerberos
                      and user is None and password is None
                      and ntlm_hash is None and creds_file is None)
    if ticket:
        if password is not None or ntlm_hash is not None or creds_file:
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
        creds = ([Credential(user="", password="", domain=domain)] if null_session
                 else resolve_credentials(user, password, ntlm_hash, domain, creds_file, combo=combo))
    stream = not json_out and not quiet
    all_json_rows = []

    targets = resolve_targets(target)
    ipv6_targets = {t for t in targets if target_uses_ipv6(t, force_ipv6=ipv6)}

    import shutil
    remote_time = None
    skew_msg = None
    if kerberos or ticket:
        time_target = kdc_host or targets[0]
        if "/" not in time_target and not Path(time_target).exists():
            remote_time = get_remote_time(time_target)
            if remote_time:
                import datetime
                try:
                    remote_dt = datetime.datetime.strptime(remote_time, "%Y-%m-%d %H:%M:%S")
                    local_dt = datetime.datetime.now()
                    offset_sec = int((remote_dt - local_dt).total_seconds())
                    
                    abs_offset = abs(offset_sec)
                    if abs_offset < 60:
                        offset_str = f"{offset_sec}s"
                    elif abs_offset < 3600:
                        offset_str = f"{offset_sec // 60}m {abs_offset % 60}s"
                    else:
                        offset_str = f"{offset_sec // 3600}h {(abs_offset % 3600) // 60}m"
                    
                    has_faketime = shutil.which("faketime") is not None
                    
                    if abs_offset >= 300:
                        if has_faketime:
                            skew_msg = (
                                f"  [dim][*] clock skew: {offset_str} (DC time: {remote_time}) — using faketime[/dim]\n"
                            )
                        else:
                            skew_msg = (
                                f"  [red][!][/red] [dim]critical clock skew of {offset_str} (DC time: {remote_time}), but [bold]faketime[/bold] is not installed. Kerberos auth will fail.[/dim]\n"
                            )
                            remote_time = None
                    else:
                        if has_faketime:
                            if debug or abs_offset >= 5:
                                skew_msg = (
                                    f"  [dim][*] clock skew: {offset_str} (DC time: {remote_time}) — using faketime[/dim]\n"
                                )
                        else:
                            remote_time = None
                except Exception:
                    pass

    try:
        if stream:
            with console.status("[bold cyan]Probing ports...[/bold cyan]"):
                port_map = _probe_targets(targets, selected, ipv6_targets, opsec)
            print_probe_summary(target, targets, port_map, selected, domain, verbose=verbose)
            if skew_msg:
                console.print(skew_msg)
        else:
            port_map = _probe_targets(targets, selected, ipv6_targets, opsec)
    except PortProbeError as exc:
        console.print(f"[red][-][/red] Port probe failed: {exc}", stderr=True)
        raise typer.Exit(code=2)

    _out_lock = threading.Lock()
    target_workers = 1 if opsec else min(len(targets), 10)

    if len(creds) > 1:
        # Validate each pair before capability mapping. Non-AD-only credentials
        # can opt out of the authentication gate via --no-auth-gate.
        pairs = [(t, cr) for t in targets for cr in creds]
        workers = 1 if opsec else min(len(pairs), 10)

        def _scan_pair(pair):
            t, cr = pair
            protos = port_map.get(t, [])
            validation = (
                verify_credential(
                    t, cr, protos, timeout,
                    local_auth=local_auth, try_local=try_local,
                    kerberos=kerberos, kdc_host=kdc_host,
                    debug=debug, remote_time=remote_time,
                    ipv6=t in ipv6_targets,
                )
                if auth_gate and not discovery_mode and protos else None
            )
            if validation is not None and not validation.ok:
                results = [validation]
            else:
                results = run_check(
                    t, cr, protos, timeout, retries, threads,
                    local_auth=local_auth, try_local=try_local,
                    kerberos=kerberos, kdc_host=kdc_host,
                    debug=debug, delay=delay, remote_time=remote_time,
                    ipv6=t in ipv6_targets, opsec=opsec,
                    list_files=list_files, verify_exec=verify_exec, enum_users=enum_users,
                )
                if validation is not None:
                    results.insert(0, validation)
            # Do not print from worker threads. During a combo scan, collect
            # results while the progress bar runs and present compact findings
            # after completion. --verbose is the explicit full transcript.
            return t, cr, results

        progress = None
        task = None
        if stream:
            progress = Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=console,
            )
            progress.start()
            task = progress.add_task(
                "Checking null session + guest access" if discovery_mode else "Validating credentials, then mapping access",
                total=len(pairs),
            )

        discovered: dict[str, dict[str, list]] = {}
        hits: list[tuple[str, Credential, list]] = []
        diagnostics: list[tuple[str, Credential, list]] = []
        verified_count = rejected_count = unclear_count = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_scan_pair, pair) for pair in pairs]
            for future in as_completed(futures):
                t, cr, results = future.result()
                if progress:
                    progress.advance(task)
                if save:
                    for result in results:
                        save_records(save, t, cr.user, result)
                if json_out:
                    all_json_rows.append({
                        "target": t, "user": cr.user, "password": cr.password,
                        "ntlm_hash": cr.ntlm_hash, "domain": cr.domain,
                        "results": [item.public_dict(raw=raw) for item in results],
                    })
                if discovery_mode:
                    discovered.setdefault(t, {})["null" if cr.user == "" else "guest"] = results
                elif not json_out:
                    gate = next((item for item in results if item.protocol == "cred"), None)
                    if gate is not None:
                        state = ("verified" if gate.ok else
                                 "rejected" if gate.level == "NO" else "unclear")
                    elif any(item.ok and item.level not in {"NO", "UNCLEAR"} for item in results):
                        state = "verified"
                    elif any(item.level == "UNCLEAR" for item in results) or not results:
                        state = "unclear"
                    else:
                        state = "rejected"

                    if state == "verified":
                        verified_count += 1
                        hits.append((t, cr, results))
                    elif state == "rejected":
                        rejected_count += 1
                    else:
                        unclear_count += 1

                    if verbose and not quiet:
                        diagnostics.append((t, cr, results))
        if progress:
            progress.stop()

        if discovery_mode and not json_out:
            for t in targets:
                print_discovery_results(t, discovered.get(t, {}), quiet=quiet,
                                        verbose=verbose or list_files)
        elif not json_out:
            # Default output: show verified credentials and their capabilities,
            # never one block for every failed/unclear combination.
            display_rows = diagnostics if verbose and not quiet else hits
            for t, cr, results in display_rows:
                if quiet:
                    print_results(t, cr, results, quiet=True)
                    continue
                print_scan_header(t, cr, domain, len(port_map.get(t, [])))
                for item in results:
                    if not verbose and (item.protocol == "cred" or item.level in {"NO", "UNCLEAR"}):
                        continue
                    print_result_event(item, verbose=verbose or (list_files and item.protocol == "smb"))

            if not quiet:
                console.print(
                    f"\\n[dim]Credential pairs: {len(pairs)} · verified: {verified_count}"
                    f" · rejected: {rejected_count} · inconclusive: {unclear_count}[/dim]",
                    highlight=False,
                )
                if verified_count == 0:
                    console.print("  [yellow]No verified credentials found.[/yellow]")
                if unclear_count and not verbose:
                    console.print("  [dim]Use --verbose for inconclusive reasons or --json for complete results.[/dim]")

    else:
        cred = creds[0]

        def _scan_single_target(t):
            target_protos = port_map.get(t, selected)
            validation = (
                verify_credential(
                    t, cred, target_protos, timeout,
                    local_auth=local_auth, try_local=try_local,
                    kerberos=kerberos, kdc_host=kdc_host,
                    debug=debug, remote_time=remote_time,
                    ipv6=t in ipv6_targets,
                )
                if auth_gate and not discovery_mode and not null_session and target_protos else None
            )
            if validation is not None and not validation.ok:
                results = [validation]
            else:
                results = run_check(
                    t, cred, target_protos, timeout, retries, threads,
                    local_auth=local_auth, try_local=try_local,
                    kerberos=kerberos, kdc_host=kdc_host,
                    debug=debug, delay=delay,
                    remote_time=remote_time,
                    ipv6=t in ipv6_targets, opsec=opsec, list_files=list_files,
                    verify_exec=verify_exec, enum_users=enum_users,
                )
                if validation is not None:
                    results.insert(0, validation)

            if stream:
                with _out_lock:
                    print_scan_header(t, cred, domain, len(target_protos))
                    if skew_msg:
                        console.print(skew_msg)
                    for r in results:
                        print_result_event(r, verbose=verbose or (list_files and r.protocol == "smb"))

            return t, results

        _scan_progress = None
        _scan_task = None
        if stream:
            _scan_progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TextColumn("·"),
                TimeRemainingColumn(),
                console=console,
            )
            _scan_progress.start()
            _scan_task = _scan_progress.add_task(
                "Scanning protocols",
                total=len(targets),
            )

        with ThreadPoolExecutor(max_workers=target_workers) as executor:
            futures = [executor.submit(_scan_single_target, t) for t in targets]
            for future in as_completed(futures):
                t, results = future.result()
                if _scan_progress:
                    _scan_progress.advance(_scan_task)

                if save:
                    for result in results:
                        save_records(save, t, cred.user, result)

                if json_out:
                    all_json_rows.append({
                        "target": t,
                        "user": cred.user,
                        "password": cred.password,
                        "ntlm_hash": cred.ntlm_hash,
                        "domain": domain,
                        "results": [r.public_dict(raw=raw) for r in results],
                    })
                elif not stream:
                    print_results(t, cred, results, quiet=quiet, verbose=verbose)

        if _scan_progress:
            _scan_progress.stop()

    if json_out:
        typer.echo(json.dumps(all_json_rows[0] if len(all_json_rows) == 1 else all_json_rows, indent=2))


if __name__ == "__main__":
    app()