# OneRun Future Roadmap & Research Plan

This document outlines the research and development goals for future versions of `onerun`.

## Research Prompts
Use these prompts with Perplexity, ChatGPT, or other LLMs to find new features:

**Prompt 1 (General Hardening):**
> "What are the most effective, modern Linux server hardening tools and scripts for 2024/2025? specifically looking for open-source tools like USBGuard, AppArmor profiles, and auditd rules that can be automated. Provide a checklist of advanced hardening steps beyond basic UFW/Fail2Ban."

**Prompt 2 (Specific Tools):**
> "How to automate the configuration of USBGuard and AppArmor on Debian and Arch Linux systems? Provide bash script examples for detecting if these tools are needed and applying safe default policies."

**Prompt 3 (Compliance):**
> "List of CIS Benchmark requirements for Linux that can be safely automated in a shell script without breaking standard services. Focus on filesystem permissions, kernel parameters, and audit logging."

## Roadmap

### v0.4 "Sentinel" (Detailed Specs)
Based on `research.md`, this version focuses on **Audit**, **USB Control**, and **Extended Kernel Hardening**.

#### 1. Advanced Kernel Hardening
**Source**: `research.md` (Part IV)
- **Action**: Extend `lib/hardening.sh` -> `apply_sysctl_hardening`.
- **New Rules**:
    - `kernel.randomize_va_space = 2` (ASLR)
    - `kernel.kptr_restrict = 2` (Restrict pointer exposure)
    - `kernel.dmesg_restrict = 1` (Restrict kernel log access)
    - `kernel.yama.ptrace_scope = 2` (Restrict ptrace)
    - `net.ipv4.tcp_syncookies = 1` (SYN flood protection)
    - `net.ipv4.conf.all.rp_filter = 1` (Anti-spoofing)
    - `net.ipv6.conf.all.forwarding = 0` (Disable IPv6 routing)

#### 2. Auditd Integration
**Source**: `research.md` (Part I, Section 2)
- **Tool**: `auditd` + `audispd-plugins`
- **Configuration**:
    - Install `auditd`.
    - Apply persistent rules in `/etc/audit/rules.d/hardening.rules`.
    - **Key Rules**:
        - Monitor `execve` (sudo execution).
        - Monitor `/etc/passwd`, `/etc/shadow`, `/etc/group` changes.
        - Monitor time changes and network modifications (`sethostname`).
    - **Optimization**: Increase buffer size (`-b 16384`) to prevent lost events.

#### 3. USBGuard Implementation
**Source**: `research.md` (Part I, Section 3)
- **Tool**: `usbguard`
- **Workflow**:
    - Install `usbguard`.
    - Generate initial policy: `usbguard generate-policy > ...` (Allow current devices).
    - Enable `usbguard-daemon`.
    - **Safety**: Ensure input devices (keyboard/mouse) are whitelisted to prevent lockout.

### v0.5 "Aegis" (AppArmor & Application Confinement)
**Goal**: Restrict application capabilities and enforce Least Privilege.

#### 1. AppArmor Automation
**Source**: `research.md` (Automating AppArmor Script)
- **Deployment Strategy**:
    - **Install**: `apparmor`, `apparmor-utils`, `apparmor-profiles`, `auditd`.
    - **Kernel Config**: Update GRUB (`GRUB_CMDLINE_LINUX_DEFAULT`) to add `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`.
    - **Bootloader**: Run `update-grub` or `grub-mkconfig`.
    - **Safety**: Deploy all profiles in **Complain Mode** (`aa-complain /etc/apparmor.d/*`) initially.
    - **Notifications**: Configure `aa-notify` for desktop alerts.

#### 2. Systemd Sandboxing
- **Objective**: Harden individual services without full MAC complexity.
- **Controls**: `CapabilityBoundingSet`, `ProtectSystem`, `ProtectHome`, `PrivateNetwork`.

### v0.6 "Compliance" (CIS Benchmarks & Lynis Enhancement)
**Goal**: Automate Level 1 CIS Benchmark recommendations and improve Lynis audit scores.

#### 1. CIS Level 1 Automation (Safe)
**Source**: `research.md` - Section I
- [ ] **Filesystem Hardening**: Disable unused modules (cramfs, hfs, hfsplus, squashfs, udf).
- [ ] **Network Hardening**: Implement remaining CIS Level 1 sysctl parameters (ICMP redirects, martians, etc.).
- [ ] **Permissions Enforcement**: Correct permissions for `/etc/passwd(-)`, `/etc/shadow(-)`, `/etc/group(-)`.

#### 2. Compliance Scanning & Reporting
- [ ] **OpenSCAP Integration**: Automated scans using `cis_level1_server` profile.
- [ ] **Lynis Optimization**: Remediation for common warnings (SSL, SSH, Permissions).
- [ ] **OneRun Compliance Report**: Aggregate findings into a consolidated summary.

#### 3. Intrusion Detection & FIM
- **Tool**: **Wazuh Agent** (Optional Integration).
- **Feature**: File Integrity Monitoring (FIM) for `/etc`, `/usr/bin`.
- **Refinement**: Integrate Wazuh agent installation for centralized monitoring.
