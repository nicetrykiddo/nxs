# nxs

[![PyPI version](https://img.shields.io/pypi/v/nxsctl.svg)](https://pypi.org/project/nxsctl/)

> What can this cred actually do?

`nxs` is a credential capability mapper powered by [NetExec](https://github.com/Pennyw0rth/NetExec). It takes a credential and checks it against 10 different protocols (SMB, LDAP, WMI, WinRM, SSH, RDP, MSSQL, FTP, VNC, NFS) to show you exactly what level of access you have on the target.

## Install

```bash
pipx install nxsctl
```

Requires [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) in PATH.

## Usage

Credential-free discovery tries **empty credentials (null session)** and **guest**
independently on each reachable protocol. The terminal shows one summary per target,
identifying whether each capability works with null credentials or guest; it does not
confuse a guest-readable share with anonymous access. `--json` keeps separate
per-credential results. This is a small, fixed access check, **not** a password spray:

```bash
nxs dc01.example.test
nxs dc01.example.test --null-session  # Empty username/password only; skip guest
```

SMB output shows readable/writable share names without requiring `--verbose`,
including shares literally named `Shares` and names containing spaces. `--list-files`
lists the **root only** of shares with READ access (not recursive), and `--enum-users`
performs optional SMB/SAMR user enumeration:

```bash
nxs dc01.example.test -u guest -p '' --list-files --enum-users
```

A reachable TCP 135 endpoint is displayed as **RPC(135)**, not confirmed WMI
management access. WMI `AUTH` alone is not proof of command execution or user enumeration.
Authentication, share permissions, and command execution are reported separately.
The `Null Auth` header is information advertised by NetExec and does not prove
anonymous file access.

All output is unredacted: the CLI, JSON, debug commands and saved evidence
show the exact supplied passwords and hashes. Use caution when sharing logs.
Saved evidence files use private permissions and unique names.
When Nmap is absent, nxs uses direct TCP checks rather than assuming every port
is open. With multiple credential pairs, nxs authenticates each pair against
LDAP/SMB first; failed pairs do not trigger capability scans. Use
`--no-auth-gate` when credentials are scoped to another protocol or
authentication cannot be verified through the preferred services.

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local
```

Password prompt if `-p` is omitted:

```bash
nxs 10.10.10.10 -u john.doe -d domain.local
```

Hash authentication:

```bash
nxs 10.10.10.10 -u john.doe -H NT_HASH -d domain.local
nxs 10.10.10.10 -u john.doe -H LM_HASH:NT_HASH -d domain.local
```

## Quickstart

IPv6-only hostnames (including `/etc/hosts`) are detected automatically. IPv4 is
preferred for dual-stack hosts unless `-6` is explicitly requested.

```bash
nxs compatibility -u test -p 'pass@123'
nxs compatibility -6 -u test -p 'pass@123'  # Force IPv6
nxs dead:beef::1001 -u test -p 'pass@123'
```

Mixed IPv4 and IPv6 target files are scanned in separate Nmap runs. Nmap failures
are reported instead of silently being treated as 0 open ports.


```bash
nxs 10.10.10.10 -u admin -p 'Password123!'

# Spray a file of credentials (format: user:pass or user:hash)
nxs 10.10.10.10 -f creds.txt

# Password spray — one password across a user list
nxs 10.10.10.10 -u users.txt -p 'Password123!'

# All combinations — every user × every password (-C/--combo)
nxs 10.10.10.10 -u users.txt -p passwords.txt -C

# Specific protocols
nxs 192.168.1.0/24 -u john.doe -H 'LM:NT' --protocols ssh,winrm
```

OPSEC mode (single-threaded, low retry):

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local --opsec
```

Kerberos:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local -k --kdc-host dc01.domain.local

# Authenticate with a ccache ticket file (no password needed):
nxs 10.10.10.10 -T user.ccache

# Scan a directory of tickets:
nxs 10.10.10.10 -T ./tickets/
```

JSON output:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --json
nxs 10.10.10.10 -u john.doe -p 'Password123' --json --raw
```

Save raw proof:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --save loot/
```

Verbose output (detailed execution info, WIP...):

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --verbose
```

## Example Output

```text
nxs v0.1.0 10.10.10.10 · john.doe@domain.local · 4 protocols

  [+] SMB    WRITE    Shared[READ+WRITE], Web[READ]
  [+] LDAP   READ     Enumerated 15 domain users
  [-] WINRM  NO       Authentication failed
```

With `--verbose`, detailed output is nested underneath. It expands share tables, metadata, and optional directory/user listings:

```text
nxs v0.1.0 10.10.10.10 · admin · 1 protocols

  [+] WINRM  EXEC     domain.local\admin
      ↳ USER INFORMATION
      ↳ ----------------
      ↳ User Name         SID
      ↳ ================= ============================================
      ↳ domain\admin      S-1-5-21-3623811015-3361044348-30300820-500
```

## Compact credential checks

With `-C`, credential validation is displayed **one pair per line** as checks
complete. No blank block per failed login. Usernames and passwords are shown
in full, while error messages use protocol failure codes rather than echoed
passwords. Only after all credentials have been checked does `nxs` probe
capabilities for verified logins:

```text
nxs v0.4.4 domain.test · probe: 4/10 ports open · WMI, LDAP, SMB, WINRM

Credential checks (3 pairs)
  [-] alice:badpass NO  LDAP: STATUS_LOGON_FAILURE
  [?] bob:guess UNCLEAR  LDAP: bind required (000004DC); SMB: guest fallback
  [+] carol:goodpass VALID  verified via LDAP: auth ok

domain.test · carol:goodpass · 4 protocols
  [+] LDAP   READ     Enumerated 3 users

Credential pairs: 3 · verified: 1 · rejected: 1 · inconclusive: 1
```

`--verbose` expands capability evidence for verified credentials without
turning rejected combinations into multi-line blocks. `--json` retains every
credential, validation outcome, and available raw record. `--no-auth-gate`
explicitly bypasses the credential-first check for protocol-specific accounts.

## Access Levels

| Level | Marker | Meaning |
|-------|--------|---------|
| `ADMIN` | `[+]` | Admin-level access |
| `EXEC` | `[+]` | Command execution |
| `WRITE` | `[+]` | Write access |
| `READ` | `[+]` | Read access |
| `AUTH` | `[*]` | Authenticated, no further access |
| `UNCLEAR` | `[?]` | Inconclusive result |
| `NO` | `[-]` | Authentication failed or port closed |

## Upgrading before a PyPI release

The GitHub code can be installed directly via:

```bash
pipx install --force 'git+https://github.com/nicetrykiddo/nxs.git'
```

The PyPI package does not update until a release is published.

## License

[MIT](LICENSE)
