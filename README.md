# OneRun: Advanced Linux System Hardening

**OneRun** is a production-ready, interactive Bash script designed to harden Linux systems (Arch, Debian/Ubuntu, Centos/RHEL) rapidly and securely.

Current Version: **v0.4 "Sentinel"**

## Features

### 🛡️ Presets
Choose your security posture:
- **Standard** (Default): Non-destructive. Removes insecure protocols (Telnet) but keeps SSH enabled. Best for most servers.
- **Hardened**: **Destructive**. Removes SSH server entirely. For high-security air-gapped or console-only systems.
- **Minimal**: Auditing only. No changes made.

### 🔒 Security Tools Manager
Automated installation and configuration of best-in-class security tools:
- **Firewall (UFW)**: Sets "Default Deny Incoming". Automatically allows SSH if enabled in preset.
- **Intrusion Prevention (Fail2Ban)**: Protects against SSH brute-force attacks.
- **Rootkit Detection (RKHunter)**: Scans for known rootkits and suspicious files.
- **Deep Audit (Lynis)**: Performs a comprehensive system security audit (CIS compliance checks).
- **System Auditing (Auditd)** (v0.4): Kernel-level event monitoring with persistent rules for `execve`, `/etc/passwd`, and network changes.
- **USB Device Control (USBGuard)** (v0.4): Prevents BadUSB attacks by whitelisting only currently connected devices.

### ⚙️ Core Hardening
- **Network Stack Hardening (Sysctl)**:
    - Protects against IP spoofing (`rp_filter`).
    - Prevents Man-in-the-Middle (MITM) redirection attacks.
    - Disables IP forwarding (unless router).
    - **Advanced Kernel Protection** (v0.4): Enables ASLR, restricts kernel pointers, and limits `ptrace` scope.
- **Secure SSH Configuration**:
    - Updates `sshd_config` to best practices.
    - **Enforced**: Key-only authentication, Root login disabled, Empty passwords disabled.
    - **Safety**: Checks for authorized keys before applying to prevent lockout.
- **User Management**: Finds users with empty passwords, locks accounts, and forces password changes.
- **File System**: Scans for dangerous SUID binaries.

## Usage

### Interactive Mode (Recommended)
```bash
git clone https://github.com/canonrebel04/onerun.git
cd onerun
sudo ./onerun.sh
```
Follow the menu prompts to select presets or individual tools.

### Automated Mode
Apply a specific preset without interaction:
```bash
# Standard Hardening (Safe)
sudo ./onerun.sh --auto --preset standard

# Hardened (Removes SSH!)
sudo ./onerun.sh --auto --preset hardened
```

### Flags
- `--preset [standard|hardened|minimal]`: Pre-selects configuration.
- `--keep-ssh`: Forces SSH to remain enabled even in Hardened mode.
- `--force`: Bypasses safety prompts (Use with caution).

## Roadmap
- **v0.4 "Sentinel"** (Current): Auditd, USBGuard, Extended Kernel Hardening.
- **v0.5**: AppArmor/SELinux Confinement.
- **v0.6**: Automated CIS Compliance Reporting.
