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

With `--verbose`, detailed output is nested underneath:

```text
nxs v0.1.0 10.10.10.10 · admin · 1 protocols

  [+] WINRM  EXEC     domain.local\admin
      ↳ USER INFORMATION
      ↳ ----------------
      ↳ User Name         SID
      ↳ ================= ============================================
      ↳ domain\admin      S-1-5-21-3623811015-3361044348-30300820-500
```

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

## License

[MIT](LICENSE)
