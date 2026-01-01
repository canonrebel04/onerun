#!/bin/bash

# CIS Compliance Hardening Library
# Implements Level 1 (Safe) recommendations from CIS Benchmarks.

cis_filesystem_hardening() {
	log_info "=== CIS 1.1.1.x - Filesystem Module Hardening ==="
	local modules=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf")
	local modprobe_file="/etc/modprobe.d/onerun-cis.conf"

	for module in "${modules[@]}"; do
		if lsmod | grep -q "^${module}" || modprobe -n -v "${module}" 2>/dev/null | grep -q "install /bin/true"; then
			log_info "Disabling module: ${module}"
			echo "install ${module} /bin/false" | sudo tee -a "${modprobe_file}" >/dev/null
			sudo modprobe -r "${module}" 2>/dev/null || true
		else
			log_info "Module ${module} already disabled or not present."
		fi
	done
	log_success "Unused filesystem modules blacklisted in ${modprobe_file}"
}

cis_network_hardening() {
	log_info "=== CIS 3.x - Extended Network Hardening ==="
	local sysctl_file="/etc/sysctl.d/99-onerun-cis.conf"

	cat <<EOF | sudo tee "${sysctl_file}" >/dev/null
# CIS 3.2.1 - Packet redirect sending disabled
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 3.3.1 - Source routed packets not accepted
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 3.3.2 - ICMP redirects not accepted
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 3.3.3 - Secure ICMP redirects not accepted
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 3.3.4 - Suspicious packets logged
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 3.3.9 - IPv6 router advertisements not accepted
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

	sudo sysctl -p "${sysctl_file}" >/dev/null 2>&1
	log_success "CIS Network parameters applied via ${sysctl_file}"
}

cis_permissions_enforcement() {
	log_info "=== CIS 6.1.x - Critical File Permissions ==="
	
	# Passwd/Group (6.1.2-6.1.5)
	sudo chown root:root /etc/passwd /etc/passwd- /etc/group /etc/group-
	sudo chmod 644 /etc/passwd /etc/passwd- /etc/group /etc/group-
	
	# Shadow/Gshadow (6.1.6-6.1.9)
	sudo chown root:shadow /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
	sudo chmod 000 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
	
	log_success "Critical file permissions enforced."
}

manage_compliance() {
	while true; do
		clear
		echo "=========================================="
		echo "   ONERUN - Compliance & CIS Benchmarks"
		echo "=========================================="
		echo "1) Apply CIS Filesystem Hardening (Disable modules)"
		echo "2) Apply CIS Network Hardening (Sysctl)"
		echo "3) Enforce Critical File Permissions"
		echo "4) Apply ALL Safe Level 1 Recommendations"
		echo "5) Back"
		echo ""
		read -p "Select Option: " choice
		
		case $choice in
			1) cis_filesystem_hardening ;;
			2) cis_network_hardening ;;
			3) cis_permissions_enforcement ;;
			4) 
				cis_filesystem_hardening
				cis_network_hardening
				cis_permissions_enforcement
				;;
			5) break ;;
			*) echo "Invalid option." ;;
		esac
		echo ""
		read -p "Press Enter to continue..."
	done
}
