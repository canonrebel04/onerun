#!/bin/bash

# Tools Management Library

check_tool_installed() {
	local tool="$1"
	if command -v "${tool}" &>/dev/null; then
		return 0
	else
		return 1
	fi
}

install_tool_wrapper() {
	local tool="$1"
	local pkg_name="$2"
	
	if check_tool_installed "${tool}"; then
		log_info "${tool} is already installed."
		return 0
	fi

	log_warn "${tool} is MISSING."
	read -r -p "Install ${pkg_name}? (y/n) " choice
	case "${choice}" in
	y | Y) 
		install_package "${pkg_name}" 
		return 0
		;;
	*) 
		log_warn "Skipping installation of ${pkg_name}."
		return 1
		;;
	esac
}

# --- Firewall (UFW) ---
manage_firewall() {
	log_info "=== Firewall Management (UFW) ==="
	
	if install_tool_wrapper "ufw" "ufw"; then
		log_info "Configuring UFW..."
		
		# Reset to default
		sudo ufw default deny incoming
		sudo ufw default allow outgoing
		
		# Allow SSH if enabled
		if [[ "${ENABLE_SSH}" == "true" ]]; then
			sudo ufw allow ssh
			log_info "Allowed SSH port."
		fi
		
		# Enable
		if ! sudo ufw status | grep -q "Status: active"; then
			echo "y" | sudo ufw enable
		fi
		
		log_success "UFW enabled and configured."
		sudo ufw status verbose
	fi
}

# --- Fail2Ban ---
manage_fail2ban() {
	log_info "=== Intrusion Prevention (Fail2Ban) ==="
	
	# Package name variance
	local pkg="fail2ban"
	
	if install_tool_wrapper "fail2ban-client" "${pkg}"; then
		log_info "Configuring Fail2Ban..."
		
		# Basic jail.local creation if not exists
		if [[ ! -f /etc/fail2ban/jail.local ]]; then
			log_info "Creating default jail.local..."
			cat <<EOF | sudo tee /etc/fail2ban/jail.local >/dev/null
[DEFAULT]
bantime  = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
		fi
		
		# Service management
		if command -v systemctl &>/dev/null; then
			sudo systemctl enable --now fail2ban
		else
			sudo service fail2ban start
		fi
		
		log_success "Fail2Ban installed and running."
		sudo fail2ban-client status
	fi
}

# --- Rootkit Detection (RKHunter) ---
run_rkhunter() {
	log_info "=== Rootkit Detection (RKHunter) ==="
	
	if install_tool_wrapper "rkhunter" "rkhunter"; then
		log_info "Updating RKHunter properties..."
		sudo rkhunter --propupd 2>&1 | grep -vE "(stray . before|egrep: warning:)" || true
		
		log_info "Running system check..."
		# Filter known grep warnings from rkhunter on newer systems
		sudo rkhunter --check --sk 2>&1 | grep -vE "(stray . before|egrep: warning:)" || true
	fi
}

# --- Deep Audit (Lynis) ---
run_lynis() {
	log_info "=== Deep System Audit (Lynis) ==="
	
	if install_tool_wrapper "lynis" "lynis"; then
		log_info "Running Lynis audit system..."
		sudo lynis audit system
	fi
}

manage_auditd() {
	log_info "=== System Auditing (Auditd) ==="
	
	# Determine package name (Debian/Ubuntu: auditd, Arch: audit)
	local pkg="auditd"
	if [[ "${PKG_MANAGER}" == "pacman" ]]; then
		pkg="audit"
	fi
	
	if install_tool_wrapper "auditctl" "${pkg}"; then
		# Check for audispd-plugins on Debian/Ubuntu
		if [[ "${PKG_MANAGER}" == "apt-get" ]]; then
			log_info "Installing audispd-plugins..."
			sudo apt-get install -y audispd-plugins >/dev/null 2>&1 || true
		fi
		
		# Ensure Log Directory Exists
		if [[ ! -d /var/log/audit ]]; then
			log_info "Creating audit log directory..."
			sudo mkdir -p /var/log/audit
			sudo chmod 0700 /var/log/audit
		fi
		
		# Configure auditd.conf to ensure logs are written
		if [[ -f /etc/audit/auditd.conf ]]; then
			log_info "Ensuring auditd.conf is configured for logging..."
			sudo sed -i 's/^write_logs.*/write_logs = yes/' /etc/audit/auditd.conf
			sudo sed -i 's/^log_format.*/log_format = RAW/' /etc/audit/auditd.conf
			sudo sed -i 's/^log_group.*/log_group = root/' /etc/audit/auditd.conf
		fi

		log_info "Configuring persistent audit rules..."
		local rules_file="/etc/audit/rules.d/hardening.rules"
		sudo mkdir -p /etc/audit/rules.d
		
		cat <<EOF | sudo tee "${rules_file}" >/dev/null
# OneRun Hardening Rules
# Buffer Size
-b 16384

# Failure Mode
-f 1

# Monitor Sudo execution
-a always,exit -F arch=b64 -S execve -F uid>=1000 -F auid>=1000 -k sudo_exec

# Monitor Critical Configuration Changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor Time Changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change

# Monitor Network Modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
EOF
		
		# auditd often refuses manual restart (RefuseManualStop=yes on Arch/Systemd)
		if command -v systemctl &>/dev/null; then
			sudo systemctl enable auditd
			# Try reload, but don't fail if it refuses or isn't running
			log_info "Reloading auditd configuration..."
			sudo systemctl reload auditd 2>/dev/null || log_warn "Auditd reload failed (expected if service is immutable). Rules will be loaded via augenrules."
		else
			sudo service auditd reload || sudo service auditd start || true
		fi
		
		# Load rules kernel-side
		if command -v augenrules &>/dev/null; then
			log_info "Loading audit rules into kernel..."
			sudo augenrules --load
		fi
		log_success "Auditd rules applied and active."
		sudo auditctl -l | head -n 5
	fi
}

manage_usbguard() {
	log_info "=== USB Device Control (USBGuard) ==="
	
	if install_tool_wrapper "usbguard" "usbguard"; then
		log_info "Generating initial USB policy (Allowing current devices)..."
		
		# CRITICAL: Generate policy BEFORE starting service to avoid lockout
		if [[ ! -f /etc/usbguard/rules.conf ]] || [[ $(stat -c%s /etc/usbguard/rules.conf) -eq 0 ]]; then
			sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf >/dev/null
			log_info "Generated whitelist for currently connected devices."
		else
			log_info "Policy file exists. Skipping generation to preserve custom rules."
		fi
		
		# Enable Service
		if command -v systemctl &>/dev/null; then
			sudo systemctl enable --now usbguard
		else
			sudo service usbguard start
		fi
		
		log_success "USBGuard is active. New USB devices will be blocked by default."
		sudo usbguard list-devices
	fi
}
