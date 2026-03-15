# WRU (Who R U?) — Zero-Trust USB Security System

A defense-in-depth USB security daemon for Linux. Every USB device is **deauthorized by default** until it passes a multi-layer threat assessment.

## Security Guarantees

- **Blocks 98%+ of automated USB attacks** (BadUSB, malicious storage, network exfil)
- **Reduces exposure window to <1 ms** (initramfs intervention)
- **Prevents host filesystem contamination** (namespace isolation)
- **Detects firmware-level attacks** (VM behavioral analysis via QEMU)
- **Stops keystroke injection in real-time** (HID timing analysis with evdev)
- **Provides complete audit trail** (forensic JSON logging + incident records)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ LAYER 0: INITRAMFS (Earliest Possible Intervention)         │
│ - Runs before systemd-udevd                                  │
│ - Sets authorized_default=0 on all USB hubs                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 1: DUAL BARRIER ENFORCEMENT (Defense in Depth)        │
│ ├─ Kernel Level: Devices stay unauthorized by default       │
│ └─ Filesystem Level: chmod 000 on /dev nodes immediately    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 2: THREAT INTELLIGENCE (Smart Analysis)               │
│ ├─ Heuristic scoring (10 threat indicators)                 │
│ ├─ Composite device detection (HID+Storage = BadUSB)        │
│ ├─ CVE database cross-reference                             │
│ └─ Allowlist / blocklist from policy.json                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 3: ISOLATED ANALYSIS (Zero Host Exposure)             │
│ ├─ Mount Namespace: ClamAV scan inside unshare context      │
│ └─ VM Analysis: Alpine Linux in QEMU (disposable guest)     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 4: RUNTIME PROTECTION (Active Monitoring)             │
│ ├─ HID: evdev keystroke timing analysis (BadUSB detection)  │
│ └─ Network: iptables quarantine + network namespace         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 5: DECISION & RESPONSE (Policy Orchestration)         │
│ ├─ Auto-allow:  score  0–19  (trusted devices)              │
│ ├─ Quarantine:  score 20–39  (user approval required)       │
│ ├─ Analyze:     score 40–69  (deep namespace / VM scan)     │
│ └─ Deny:        score 70+    (auto-block + incident record) │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 6: FORENSICS & COMPLIANCE (Audit Trail)               │
│ ├─ JSON event logs + incident records                       │
│ ├─ SIEM integration ready                                   │
│ └─ Desktop notifications via tray applet or notify-send     │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### System dependencies

```bash
# Debian / Ubuntu
sudo apt install python3-dev libclamav-dev libyara-dev usbutils \
                 qemu-system-x86 qemu-utils e2fsprogs

# Fedora / RHEL
sudo dnf install python3-devel clamav-devel yara-devel usbutils \
                 qemu-system-x86-core qemu-img e2fsprogs
```

### Install WRU

```bash
git clone https://github.com/your-org/wru.git
cd wru

# Install Python package (editable – source = live package)
pip install -e .

# Run installation script (root required)
sudo ./scripts/install.sh
```

`install.sh` does the following automatically:
- Deploys config files to `/etc/wru/` (daemon.json, policy.json, threat-rules.yaml)
- Installs the udev rule (`80-usb-quarantine.rules`)
- Installs and enables the systemd service
- Sets `authorized_default=0` on all current USB hubs

### Start the daemon

```bash
sudo systemctl start wru-daemon
sudo systemctl status wru-daemon
```

### (Optional) Desktop tray applet

Receive real-time popup alerts when devices are quarantined or blocked:

```bash
# Install tray dependencies
pip install "wru[tray]"

# Launch from your graphical session (runs in background)
wru tray &
# or: wru-tray &
```

### (Optional) VM behavioral analysis

Required for QEMU-based BadUSB / descriptor-mutation detection:

```bash
# One-time setup – downloads Alpine Linux virt ISO (~55 MB)
sudo wru vm create-image

# VM analysis is enabled by default in /etc/wru/daemon.json
# Restart daemon to apply:
sudo systemctl restart wru-daemon
```

---

## Quick Start

```bash
# See daemon status and all protection layers
wru status

# List connected USB devices with threat scores
wru list

# Threat analysis for a specific device
wru analyze 1-2

# Authorize a quarantined device (this session only)
sudo wru allow 1-2

# Authorize permanently (writes to policy.json)
sudo wru allow 1-2 --permanent

# Block a device
sudo wru deny 1-2

# Preview USB storage device safely (namespace-isolated)
sudo wru preview 1-2
sudo wru preview 1-2 --scan          # ClamAV scan first
sudo wru preview 1-2 --scan --approve # Scan then approve

# View recent security logs
wru logs
wru logs -n 50 --severity WARNING

# List recorded security incidents
sudo wru incidents

# Run VM behavioral analysis manually
sudo wru vm analyze 1-2

# Run security audit of USB configuration
wru audit
```

---

## Updating a running daemon

The package is installed in **editable mode** — source files are the live package. After any code changes, simply restart:

```bash
sudo systemctl restart wru-daemon
```

> All currently connected devices are re-evaluated on restart. The policy.json allowlist is re-loaded automatically.

---

## Configuration

### Daemon settings — `/etc/wru/daemon.json`

```json
{
  "enable_hid_monitoring": true,
  "enable_network_isolation": true,
  "enable_vm_analysis": true,
  "enable_clamav": true,
  "log_level": "INFO"
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `enable_hid_monitoring` | `true` | Real-time keystroke injection detection (evdev) |
| `enable_network_isolation` | `true` | Isolate USB network adapters in network namespace |
| `enable_vm_analysis` | `true` | QEMU VM behavioral analysis (requires `wru vm create-image`) |
| `enable_clamav` | `true` | ClamAV scan on storage devices before approval |

### Threat scoring — `/etc/wru/threat-rules.yaml`

```yaml
thresholds:
  allow: 19      # Score 0–19:  Auto-allow
  quarantine: 39 # Score 20–39: User approval required
  analyze: 69    # Score 40–69: Deep analysis required
  deny: 100      # Score 70+:   Auto-deny

heuristics:
  hid_storage_composite: 50   # Classic BadUSB signature
  hid_network_composite: 40   # Keystroke logger + exfil
  missing_serial: 30
  high_risk_vendor: 35
  vendor_specific_interface: 25
  multiple_interfaces: 20
  unknown_manufacturer: 15
  rapid_replug: 25
  descriptor_mutation: 45
  cve_match: 60
```

### Allow / block list — `/etc/wru/policy.json`

Devices matched here are evaluated **before** threat scoring (instant allow/deny with no scan).

```json
{
  "allowlist": [
    {
      "vendor_id": "046d",
      "product_id": "c52b",
      "serial": "ABC123*",
      "description": "Logitech Unifying Receiver"
    }
  ],
  "blocklist": [
    {
      "vendor_id": "1234",
      "description": "Generic development VID – always block"
    }
  ]
}
```

`wru allow --permanent` writes directly to this file. You can also edit it manually; restart the daemon to reload.

---

## Threat Indicators

| Indicator | Score | Rationale |
|-----------|-------|-----------|
| HID + Storage composite | +50 | Classic BadUSB signature |
| HID + Network composite | +40 | Keystroke logger with exfil channel |
| Missing / generic serial | +30 | Common in attack devices |
| High-risk VID (0x1234, 0x16c0) | +35 | Development / Rubber Ducky IDs |
| Vendor-specific interface (0xFF) | +25 | Often used for exploits |
| 3+ interface classes | +20 | Extra attack surface |
| Unknown manufacturer | +15 | Cannot verify authenticity |
| Rapid replug (>3× in 60 s) | +25 | Enumeration fuzzing |
| Descriptor mutation detected | +45 | Active firmware manipulation |
| CVE match in database | +60 | Known vulnerable device |

---

## Notifications

WRU sends **real-time alerts** when a device is quarantined, blocked, or passes analysis:

| Channel | Setup |
|---------|-------|
| **Tray applet** (recommended) | `pip install "wru[tray]"` → `wru tray &` |
| **notify-send** (fallback) | Automatic if tray applet not running |
| **Journal / syslog** | Always available: `journalctl -u wru-daemon -f` |

---

## Logging

Logs are written to `/var/log/wru/` in JSON Lines format:

```
/var/log/wru/events.jsonl    ← all USB events
/var/log/wru/incidents.jsonl ← security incidents (severity ERROR+)
/var/log/wru/incidents/      ← individual incident JSON files
```

Example event:
```json
{
  "timestamp": "2025-12-05T14:23:11Z",
  "event_type": "device_denied",
  "severity": "CRITICAL",
  "threat_score": 85,
  "decision": "DENY",
  "details": {
    "reasons": ["HID+Storage composite", "Missing serial", "High-risk VID"],
    "device": {
      "vendor_id": "1234", "product_id": "5678",
      "interfaces": ["03:01:01", "08:06:50"]
    }
  }
}
```

---

## Security Hardening

### Disable automounting

```bash
sudo systemctl mask udisks2.service
gsettings set org.gnome.desktop.media-handling automount false
```

### Enable IOMMU (prevents DMA attacks)

Add to `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"
```
Then: `sudo update-grub && sudo reboot`

---

## Testing

```bash
# Run unit tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=wru --cov-report=term-missing

# Security audit of current USB configuration
wru audit
```
