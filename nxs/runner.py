from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .models import CommandRecord, Credential, ProtocolResult

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
PERM_RE = re.compile(r"\s(?P<share>[A-Za-z0-9.$_-]+)\s+(?P<perm>READ,WRITE|READ|WRITE)(?:\s|$)")

HARD_FAILS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "KDC_ERR_PREAUTH_FAILED",
    "Authentication failed",
    "LOGIN_FAILED",
)

EXEC_DENIED = (
    "STATUS_ACCESS_DENIED",
    "rpc_s_access_denied",
    "access is denied",
    "WinRM::WinRMAuthorizationError",
)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


_active_procs: set[subprocess.Popen] = set()
_proc_lock = threading.Lock()


def kill_all_procs() -> None:
    with _proc_lock:
        for proc in _active_procs:
            try:
                proc.kill()
            except OSError:
                pass


_nxc_cache: str | None = None

def find_nxc() -> str:
    global _nxc_cache
    if _nxc_cache:
        return _nxc_cache
    path = shutil.which("nxc") or shutil.which("netexec")
    if not path:
        from rich.console import Console
        Console(stderr=True).print("[red][-][/red] nxc/netexec not found in PATH")
        raise SystemExit(1)
    _nxc_cache = path
    return path


def run_command(command: list[str], timeout: int, debug: bool = False, env: dict | None = None) -> CommandRecord:
    if debug:
        print("[debug]", " ".join(command))
    try:
        proc = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        with _proc_lock:
            _active_procs.add(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return CommandRecord(command[:], 124, "TIMEOUT")
        finally:
            with _proc_lock:
                _active_procs.discard(proc)
        output = strip_ansi((stdout or "") + (stderr or ""))
        return CommandRecord(command[:], proc.returncode, output)
    except OSError as e:
        return CommandRecord(command[:], 1, str(e))


def auth_args(cred: Credential, kerberos: bool = False, kdc_host: str | None = None) -> list[str]:
    args = ["-u", cred.user]

    if cred.ccache_file:
        args += ["--use-kcache"]
    elif cred.ntlm_hash:
        args += ["-H", cred.ntlm_hash]
    else:
        args += ["-p", cred.password or ""]

    if cred.domain:
        args += ["-d", cred.domain]
    if kerberos or cred.ccache_file:
        args += ["-k"]
    if kdc_host:
        args += ["--kdcHost", kdc_host]

    return args


def build_cmd(
    nxc: str,
    protocol: str,
    target: str,
    cred: Credential,
    extra: list[str] | None = None,
    local_auth: bool = False,
    kerberos: bool = False,
    kdc_host: str | None = None,
) -> list[str]:
    command = [nxc, protocol, target] + auth_args(cred, kerberos, kdc_host)

    if local_auth and protocol in {"smb", "wmi"}:
        command.append("--local-auth")
    if extra:
        command += extra

    return command


PORT_MAP = {
    "smb": "445",
    "ldap": "389",
    "wmi": "135",
    "winrm": "5985",
    "ssh": "22",
    "rdp": "3389",
    "mssql": "1433",
    "ftp": "21",
    "vnc": "5900",
    "nfs": "2049",
}

def check_port_state(target: str, protocol: str) -> str:
    port = PORT_MAP.get(protocol)
    if not port:
        return "port closed / filtered"

    nmap = shutil.which("nmap")
    if not nmap:
        return "port closed / filtered"

    try:
        result = subprocess.run(
            [nmap, "-Pn", "-p", port, target],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.splitlines():
            if f"{port}/tcp" in line:
                if "filtered" in line:
                    return "port filtered"
                elif "closed" in line:
                    return "port closed"
    except Exception:
        pass

    return "port closed / filtered"


def probe_ports(target: str, protocols: list[str], timeout: int = 5) -> list[str]:
    """Quick TCP probe — returns only protocols whose ports are open."""
    nmap = shutil.which("nmap")
    if not nmap:
        return protocols[:]

    ports = [PORT_MAP[p] for p in protocols if p in PORT_MAP]
    if not ports:
        return protocols[:]

    port_to_proto = {PORT_MAP[p]: p for p in protocols if p in PORT_MAP}

    try:
        result = subprocess.run(
            [nmap, "-Pn", "-T4", "-p", ",".join(ports), target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        reachable = []
        for line in result.stdout.splitlines():
            for port, proto in port_to_proto.items():
                if f"{port}/tcp" in line and "open" in line and "filtered" not in line:
                    reachable.append(proto)
        return reachable
    except Exception:
        return protocols[:]


def auth_state(output: str, user: str, target: str, protocol: str) -> tuple[bool | None, str]:
    if not output.strip():
        return False, check_port_state(target, protocol)

    low = output.lower()
    user_low = user.lower()

    for fail in HARD_FAILS:
        if fail.lower() in low:
            return False, fail

    if "nt_status_io_timeout" in low:
        return False, "timeout"
    if "timeout" in low:
        return False, "timeout"
    if "connection refused" in low:
        return False, check_port_state(target, protocol)
    if "no route" in low or "unreachable" in low:
        return False, "unreachable"

    success_lines = [line for line in output.splitlines() if "[+]" in line]
    failure_lines = [line for line in output.splitlines() if "[-]" in line]

    if any(user_low in line.lower() for line in success_lines):
        return True, "auth ok"
    if success_lines:
        return True, "auth ok"

    def _extract_reason(line: str) -> str:
        if "[-]" in line:
            msg = line.split("[-]", 1)[1].strip()
            
            # Split out words to check if the first one is the username
            parts = msg.split()
            if parts:
                first_word = parts[0].lower()
                # The username might have a domain prefix: DOMAIN\user
                if user_low in first_word or first_word in user_low:
                    msg = " ".join(parts[1:])
                    # Clean up Kerberos ccache specific clutter
                    if msg.startswith("from ccache "):
                        msg = msg[12:]
            return msg
        return "auth failed"

    for line in failure_lines:
        if user_low in line.lower():
            return False, _extract_reason(line)
            
    if failure_lines:
        return False, _extract_reason(failure_lines[0])

    return None, "no clear auth result"


def smb_capability(output: str) -> tuple[str, str]:
    shares: list[str] = []
    is_admin = False

    for line in output.splitlines():
        match = PERM_RE.search(line)
        if not match:
            continue

        share = match.group("share")
        perm = match.group("perm")

        if share.upper() in {"ADMIN$", "C$"} and "WRITE" in perm:
            is_admin = True

        if share.upper() in {"IPC$", "ADMIN$", "C$"}:
            continue

        shares.append(f"{share}[{perm.replace(',', '+')}]")

    if is_admin:
        detail = ", ".join(shares) if shares else "admin shares writable"
        return "ADMIN", detail
    if any("WRITE" in item for item in shares):
        return "WRITE", ", ".join(shares)
    if shares:
        return "READ", ", ".join(shares)

    return "AUTH", "auth ok"


def ldap_capability(output: str) -> tuple[str, str]:
    for line in output.splitlines():
        if "Enumerated" in line and ("domain users" in line or "users" in line):
            return "READ", line.split("[*]")[-1].strip()

    if "[+]" in output:
        return "READ", "bind ok"

    return "AUTH", "auth ok"


def exec_capability(output: str) -> tuple[str, str]:
    low = output.lower()

    if any(item.lower() in low for item in EXEC_DENIED):
        return "AUTH", "auth ok, exec denied"

    ok, _ = auth_state(output, "", "", "")

    if ok:
        capture = False
        for line in output.splitlines():
            if "[+]" in line:
                capture = True
                continue
            if capture and line.strip():
                out = line.strip()
                match = re.match(r"^[A-Za-z]+\s+[a-fA-F0-9\.\:]+\s+\d+\s+\S+\s+(.*)", out)
                if match:
                    out = match.group(1).strip()
                return "EXEC", out

        return "EXEC", "command execution"

    return "AUTH", "auth ok"


def save_records(save_dir: Path, target: str, user: str, result: ProtocolResult) -> None:
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", user)

    base = save_dir / safe_target / safe_user
    base.mkdir(parents=True, exist_ok=True)

    for idx, record in enumerate(result.records, start=1):
        path = base / f"{result.protocol}_{idx}.txt"
        path.write_text(
            "$ " + " ".join(record.command) + "\n\n" + record.output,
            encoding="utf-8",
            errors="replace",
        )


def test_protocol(
    target: str,
    protocol: str,
    cred: Credential,
    timeout: int = 30,
    retries: int = 1,
    local_auth: bool = False,
    try_local: bool = False,
    kerberos: bool = False,
    kdc_host: str | None = None,
    debug: bool = False,
    delay: float = 0.0,
) -> ProtocolResult:
    nxc = find_nxc()
    ccache_env = {**os.environ, "KRB5CCNAME": str(cred.ccache_file)} if cred.ccache_file else None
    modes = [local_auth]

    if try_local and not local_auth and protocol in {"smb", "wmi"}:
        modes.append(True)

    all_records: list[CommandRecord] = []
    last_reason = "no clear auth result"

    for mode in modes:
        for attempt in range(retries + 1):
            if delay and attempt:
                time.sleep(delay)

            login = run_command(
                build_cmd(nxc, protocol, target, cred, local_auth=mode, kerberos=kerberos, kdc_host=kdc_host),
                timeout,
                debug,
                env=ccache_env,
            )

            all_records.append(login)
            ok, reason = auth_state(login.output, cred.user, target, protocol)
            last_reason = reason

            if ok is False:
                return ProtocolResult(protocol, False, "NO", reason, "local" if mode else "domain", all_records)

            if ok is not True:
                continue

            level, proof = "AUTH", "auth ok"

            if protocol == "smb":
                shares = run_command(
                    build_cmd(nxc, protocol, target, cred, ["--shares"], mode, kerberos, kdc_host),
                    timeout,
                    debug,
                    env=ccache_env,
                )
                all_records.append(shares)

                share_ok, _ = auth_state(shares.output, cred.user, "", "")
                if share_ok:
                    level, proof = smb_capability(shares.output)

            elif protocol == "ldap":
                users = run_command(
                    build_cmd(nxc, protocol, target, cred, ["--users"], mode, kerberos, kdc_host),
                    timeout,
                    debug,
                    env=ccache_env,
                )
                all_records.append(users)

                ldap_ok, _ = auth_state(users.output, cred.user, "", "")
                if ldap_ok:
                    level, proof = ldap_capability(users.output)

            elif protocol in {"ssh", "winrm", "wmi"}:
                if protocol == "ssh":
                    cmd_args = ["-x", "id; uname -a; cat /etc/os-release | grep PRETTY_NAME"]
                elif protocol == "winrm":
                    cmd_args = ["-x", "whoami & echo. & whoami /all"]
                else:
                    cmd_args = ["-x", "whoami"]
                
                exec_check = run_command(
                    build_cmd(nxc, protocol, target, cred, cmd_args, mode, kerberos, kdc_host),
                    timeout,
                    debug,
                    env=ccache_env,
                )
                all_records.append(exec_check)
                level, proof = exec_capability(exec_check.output)

            return ProtocolResult(protocol, True, level, proof, "local" if mode else "domain", all_records)

    return ProtocolResult(protocol, False, "UNCLEAR", last_reason, "local" if local_auth else "domain", all_records)
