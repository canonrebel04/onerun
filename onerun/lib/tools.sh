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
