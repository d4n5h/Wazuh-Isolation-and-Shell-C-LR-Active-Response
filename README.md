# Wazuh Isolation and Shell C-LR Active Response

[mitzep0x1/C-LiveResponse](https://github.com/mitzep0x1/C-LiveResponse) ported to Go and extended support to multiple platforms

## Why Go?


|                  | mitzep0x1/C-LiveResponse         | This                            |
| ---------------- | -------------------------------- | ------------------------------- |
| Binary size      | ~15-30 MB                        | ~2 MB                           |
| Runtime deps     | Bundled Python interpreter       | None                            |
| Startup time     | ~1-3s                            | Instant                         |
| Platform support | Windows only                     | Windows, Linux, macOS           |
| Legacy support   | Requires matching Python version | Go 1.20 targets Server 2008 R2+ |

## Modules

### Isolation

Network containment via platform-native firewalls. Blocks all traffic except whitelisted IPs (e.g. Wazuh manager).

| Platform | Backend                                  |
| -------- | ---------------------------------------- |
| Windows  | `netsh advfirewall`                      |
| Linux    | `nftables` (auto-fallback to `iptables`) |
| macOS    | `pfctl`                                  |

### Shell

Remote command execution with output batched back to Wazuh logs.

| Platform      | Executor     |
| ------------- | ------------ |
| Windows       | `cmd /c`     |
| Linux / macOS | `/bin/sh -c` |

## Build

Requires Go 1.21+. For legacy Windows (Server 2008 R2), also install Go 1.20:

```powershell
go install golang.org/dl/go1.20.14@latest
go1.20.14 download
```

Build all 7 targets:

```powershell
.\build.ps1
```

```bash
chmod +x build.sh   # first time only
./build.sh          # optional: ./build.sh dist
```

### Output

```text
bin/
├── legacy-amd64/     # Windows Server 2008 R2+ / Win7+ (Go 1.20)
├── windows-amd64/    # Windows Server 2016+ / Win10+
├── windows-arm64/    # Windows 11 ARM
├── linux-amd64/
├── linux-arm64/
├── darwin-amd64/
└── darwin-arm64/
```

Each folder contains `isolation` + `shell` (with `.exe` extension on Windows).

## Binary Compatibility Guide

### Windows


| Binary           | OS Versions                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `legacy-amd64/`  | Windows 7, 8, 8.1, 10, 11 / Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022 |
| `windows-amd64/` | Windows 10 1809+, 11 / Server 2016, 2019, 2022, 2025                        |
| `windows-arm64/` | Windows 11 ARM / Server 2025 ARM                                            |


Use **legacy-amd64** if you have any endpoints running Server 2008 R2 through 2012 R2 or Windows 7/8.x. For anything Server 2016 or newer, use **windows-amd64** (smaller, faster binary built with latest Go).

### Linux


| Binary         | Architecture | Distros                                                 |
| -------------- | ------------ | ------------------------------------------------------- |
| `linux-amd64/` | x86_64       | Ubuntu, Debian, RHEL, CentOS, Rocky, Amazon Linux, SLES |
| `linux-arm64/` | aarch64      | AWS Graviton, Raspberry Pi 4+, Oracle ARM               |


Firewall backend is auto-detected at runtime: `nftables` if `nft` is in PATH, otherwise falls back to `iptables`.

### macOS


| Binary          | Architecture  | Hardware                        |
| --------------- | ------------- | ------------------------------- |
| `darwin-amd64/` | Intel x86_64  | MacBook/iMac/Mac Pro (pre-2020) |
| `darwin-arm64/` | Apple Silicon | M1, M2, M3, M4+                 |


Apple Silicon Macs can also run `darwin-amd64` via Rosetta 2, but prefer the native `darwin-arm64` binary.

## Deploy

Copy the appropriate binaries to the Wazuh active-response directory:


| Platform | Path                                                      |
| -------- | --------------------------------------------------------- |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| Linux    | `/var/ossec/active-response/bin/`                         |
| macOS    | `/Library/Ossec/active-response/bin/`                     |


Restart the Wazuh agent:

```powershell
# Windows
Restart-Service -Name wazuh

# Linux / macOS
systemctl restart wazuh-agent
```

## Usage (Wazuh API)

Commands are sent via the Wazuh API (`PUT /active-response`) from the DevTools console or any API client.

### Isolation

Contain a compromised host by blocking all network traffic except to whitelisted IPs (e.g. Wazuh manager). Restore with `release`.

**Isolate:**

```json
PUT /active-response?agents_list=001
{
  "command": "!isolation.exe",
  "arguments": ["192.168.1.1", "192.168.1.2"],
  "alert": {
    "data": {
      "action": "isolate",
      "user": "c-137labs",
      "debug": false
    }
  }
}
```

**Release:**

```json
PUT /active-response?agents_list=001
{
  "command": "!isolation.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "release",
      "user": "c-137labs",
      "debug": false
    }
  }
}
```


| Parameter           | Description                                                                         |
| ------------------- | ----------------------------------------------------------------------------------- |
| `agents_list`       | Agent ID(s) to target. Accepts comma-separated list.                                |
| `command`           | Binary name prefixed with `!` for Wazuh execution. On Linux/macOS use `!isolation`. |
| `arguments`         | IPs allowed during isolation (e.g. Wazuh server, jump host).                        |
| `alert.data.action` | `isolate` or `release`                                                              |
| `alert.data.user`   | Analyst identity for audit trail.                                                   |
| `alert.data.debug`  | Write debug log to `isolation.log`. Set `false` in production.                      |


### Shell

Execute CMD, PowerShell, or shell commands remotely. Output is batched into 50-line chunks and logged to `active-responses.log`, viewable in Wazuh Discover.

**Windows CMD:**

```json
PUT /active-response?agents_list=001
{
  "command": "!shell.exe",
  "arguments": ["cmd /c net user"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Windows PowerShell:**

```json
PUT /active-response?agents_list=001
{
  "command": "!shell.exe",
  "arguments": ["powershell -c Get-NetTCPConnection -State Established"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Linux / macOS:**

```json
PUT /active-response?agents_list=002
{
  "command": "!shell",
  "arguments": ["ps aux | grep suspicious"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```


| Parameter          | Description                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `agents_list`      | Agent ID(s) to target.                                                                                           |
| `command`          | `!shell.exe` (Windows) or `!shell` (Linux/macOS).                                                                |
| `arguments`        | Command string. Windows requires `cmd /c` or `powershell -c` prefix. Linux/macOS runs via `/bin/sh -c` directly. |
| `alert.data.user`  | Analyst identity for audit trail. Required — command is rejected without it.                                     |
| `alert.data.debug` | Write debug log to `shell.log`. Set `false` in production.                                                       |


## Project Structure

```
├── build.ps1                        # Cross-platform build (Windows)
├── build.sh                         # Cross-platform build (Linux / macOS)
├── go.mod
├── cmd/
│   ├── isolation/
│   │   ├── main.go                  # Entry point, validation, dispatch
│   │   ├── firewall_windows.go      # netsh advfirewall
│   │   ├── firewall_linux.go        # iptables / nftables
│   │   └── firewall_darwin.go       # pfctl
│   └── shell/
│       ├── main.go                  # Entry point, output batching
│       ├── exec_windows.go          # cmd /c
│       └── exec_unix.go             # /bin/sh -c
└── internal/
    └── shared/
        ├── shared.go                # Types, JSON I/O, logging
        ├── paths_windows.go
        ├── paths_linux.go
        └── paths_darwin.go
```

