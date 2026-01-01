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

### v0.4 "Sentinel" (Proposed)
Focus: **Access Control & Integrity**
- [ ] **USBGuard Integration**:
    - Detect current USB devices.
    - Generate a whitelist policy (`usbguard generate-policy`).
    - Install and enable `usbguard-daemon`.
- [ ] **Advanced Auditd Rules**:
    - Deploy the "Neo23x0/auditd" best-practice ruleset.
    - Configure immutable audit rules (`-e 2`).
- [ ] **File Integrity Monitoring (AIDE)**:
    - Automate `aide --init` and daily checks.

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
