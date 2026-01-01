#!/bin/bash

# Hardening functions

remove_ssh() {
	if [[ "${ENABLE_SSH}" == "true" ]]; then
		log_warn "SSH removal skipped (ENABLE_SSH=true). Removing Telnet only..."
		remove_package "telnet" || true
		return
	fi

	safety_check "Remove SSH Server and Telnet entirely?" || return
	force_remove_ssh
}

force_remove_ssh() {
	log_info "Removing SSH keys/directories..."
	remove_dot_ssh

	log_info "Stopping and disabling SSH service..."
	# OS independent stop
	if command -v systemctl &>/dev/null; then
		sudo systemctl stop sshd ssh 2>/dev/null
		sudo systemctl disable sshd ssh 2>/dev/null
	else
		sudo service ssh stop 2>/dev/null
		sudo service sshd stop 2>/dev/null
	fi

	log_info "Removing SSH packages..."
	remove_package "openssh-server"
	remove_package "telnet"

	# Specific cleanup based on OS
	if [[ ${PKG_MANAGER} == "apt-get" ]]; then
		sudo apt-get purge -y openssh-server telnet*
		sudo apt-get autoremove -y
		# Pinning
		echo "Package: openssh-server" | sudo tee -a /etc/apt/preferences.d/block-ssh >/dev/null
		echo "Pin: version *" | sudo tee -a /etc/apt/preferences.d/block-ssh >/dev/null
		echo "Pin-Priority: -1" | sudo tee -a /etc/apt/preferences.d/block-ssh >/dev/null
		log_info "APT pinning applied for openssh-server"
	elif [[ ${PKG_MANAGER} == "yum" || ${PKG_MANAGER} == "dnf" ]]; then
		# RedHat specific cleanup
		if ! grep -F -q "exclude=openssh*" /etc/yum.conf; then
			echo 'exclude=openssh*' | sudo tee -a /etc/yum.conf
			log_info "Added exclude=openssh* to /etc/yum.conf"
		fi
	fi

	# Common cleanup
	sudo rm -rf /etc/ssh /root/.ssh
}

secure_ssh_config() {
	safety_check "Configure SSH securely (Disable Root Login, Disable Passwords)?" || return

	# Pre-flight check for authorized_keys
	local user_home
	user_home=$(eval echo "~${SUDO_USER:-$USER}")
	if [[ ! -f "${user_home}/.ssh/authorized_keys" ]]; then
		log_warn "No authorized_keys found for ${SUDO_USER:-$USER}."
		log_warn "Enabling key-only authentication would LOCK YOU OUT."
		read -r -p "Abort? (Y/n) " choice
		if [[ "${choice}" =~ ^[Yy]$ ]]; then
			return 1
		fi
	fi

	log_info "Securing SSH configuration..."
	local sshd_config="/etc/ssh/sshd_config"
	
	if [[ -f "${sshd_config}" ]]; then
		# Backup first
		sudo cp "${sshd_config}" "${sshd_config}.bak.$(date +%F)"
		log_info "Backed up sshd_config."

		# Apply settings using sed to replace or append
		# Helper to set config
		set_ssh_param() {
			local param="$1"
			local value="$2"
			if grep -q "^#\?${param}" "${sshd_config}"; then
				sudo sed -i "s/^#\?${param}.*/${param} ${value}/" "${sshd_config}"
			else
				echo "${param} ${value}" | sudo tee -a "${sshd_config}" >/dev/null
			fi
		}

		set_ssh_param "PermitRootLogin" "no"
		set_ssh_param "PasswordAuthentication" "no"
		set_ssh_param "ChallengeResponseAuthentication" "no"
		set_ssh_param "PubkeyAuthentication" "yes"
		
		# Validate config before restart
		if sudo sshd -t; then
			log_success "SSH config verified."
			if command -v systemctl &>/dev/null; then
				sudo systemctl reload sshd
			else
				sudo service sshd reload
			fi
			log_success "SSH secure configuration applied."
		else
			log_error "SSH config validation failed! Restoring backup..."
			sudo mv "${sshd_config}.bak.$(date +%F)" "${sshd_config}"
		fi
	else
		log_error "sshd_config not found at ${sshd_config}"
	fi
}

apply_sysctl_hardening() {
	log_info "Applying Sysctl Network Hardening..."
	
	local conf_file="/etc/sysctl.d/99-onerun-hardening.conf"
	
	cat <<EOF | sudo tee "${conf_file}" >/dev/null
# ONERUN Hardening Rules
# Prevent Man-in-the-Middle attacks
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Log suspicious Martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IP Forwarding (unless router)
net.ipv4.ip_forward = 0

# Ignore ICMP Broadcasts (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Randomize kernel memory addresses (ASLR)
kernel.randomize_va_space = 2

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict kernel log access (prevention of info leaks)
kernel.dmesg_restrict = 1

# Restrict ptrace (prevent process inspection attacks)
kernel.yama.ptrace_scope = 2

# SYN Flood Protection
net.ipv4.tcp_syncookies = 1

# Reverse Path Filtering (Anti-Spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

	# Apply changes
	if sudo sysctl -p "${conf_file}"; then
		log_success "Sysctl hardening rules applied."
	else
		log_error "Failed to apply sysctl rules."
	fi
}

remove_dot_ssh() {
	log_info "Removing .ssh directories for all users..."
	sudo rm -rf /root/.ssh

	# Users from /etc/passwd who have /home directories
	while IFS=: read -r user home; do
		if [[ -d "${home}/.ssh" ]]; then
			log_info "Removing .ssh for ${user}"
			sudo rm -rf "${home}/.ssh"
		fi
	done < <(awk -F: '/\/home/ {print $1":"$6}' /etc/passwd || true)
}

change_all_pass() {
	safety_check "Change ALL user passwords interactively?" || return

	#Get interactive users (uid >= 1000)
	while read -r user; do
		echo "Changing password for ${user}"
		sudo passwd "${user}"
	done < <(awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd || true)
}

users_no_pass() {
	log_info "Checking for users without passwords..."
	local nopass
	nopass=$(sudo passwd -S -a | grep -E " NP | PS " | awk '{print $1}' || true)

	if [[ -z ${nopass} ]]; then
		log_info "No users without passwords found."
		return
	fi

	echo "Users without passwords: ${nopass}"
	for user in ${nopass}; do
		read -r -p "Set password for ${user}? (y/n/skip-all) " choice
		case ${choice} in
		y | Y) sudo passwd "${user}" ;;
		s | skip-all) return ;;
		*) echo "Skipping ${user}" ;;
		esac
	done
}

motd() {
	log_info "Setting secure MOTD..."
	echo "UNAUTHORIZED ACCESS PROHIBITED" | sudo tee /etc/motd /etc/issue >/dev/null
}

init_passwords() {
	log_info "Initializing admin passwords..."
	echo "Change password for CURRENT USER (${USER})"
	sudo passwd "${USER}"
	echo "Change password for ROOT"
	sudo passwd root
}
