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

### v0.5 "Aegis" (Proposed)
Focus: **Application Confinement**
- [ ] **AppArmor/SELinux Automation**:
    - Install default profiles.
    - Set profiles to "complain" mode initially (safe learning).
- [ ] **Systemd Sandboxing**:
    - script to harden specific service units (e.g., `nginx`, `apache`) using `systemd-analyze security` suggestions.

### v0.6 "Bastion" (Proposed)
Focus: **Compliance & Reporting**
- [ ] **CIS Benchmark Audit**:
    - Automated check script against simplified CIS rules.
- [ ] **HTML Report Generation**:
    - Generate a consolidated dashboard of system security status.
