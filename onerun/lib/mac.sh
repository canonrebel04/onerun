#!/bin/bash

# AppArmor Management Library
# Handles installation, kernel parameter configuration, and profile mode switching.

install_apparmor_tools() {
	log_info "Installing AppArmor tools..."
	if [[ "${PKG_MANAGER}" == "pacman" ]]; then
		install_package "apparmor"
		install_package "audit"
	else
		install_package "apparmor"
		install_package "apparmor-utils"
		install_package "apparmor-profiles"
		install_package "auditd"
		# Debian/Ubuntu specific extra profiles and notifications
		install_package "apparmor-profiles-extra" || true
		install_package "apparmor-notify" || true
	fi
}

enable_apparmor_grub() {
	log_step "Configuring GRUB for AppArmor..."
	local grub_file="/etc/default/grub"

	if [[ ! -f "$grub_file" ]]; then
		log_warn "GRUB configuration not found at $grub_file. Skipping bootloader config."
		return 0
	fi

	backup_file "$grub_file" "grub_apparmor"

	local lsm_string="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"

	if grep -q "apparmor" "$grub_file"; then
		log_info "AppArmor appears to be already configured in GRUB."
	else
		log_info "Adding AppArmor LSM parameters to GRUB..."
		# Check if lsm is already there to avoid duplicates or conflict
		if grep -q "lsm=" "$grub_file"; then
			log_warn "Existing 'lsm=' parameter found. Please manually check if apparmor is included in $grub_file."
		else
			# Safely inject into GRUB_CMDLINE_LINUX_DEFAULT
			# We assume standard format: GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
			sudo sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"${lsm_string} /" "$grub_file"

			log_info "Updating GRUB configuration..."
			if command -v update-grub &>/dev/null; then
				sudo update-grub
			elif command -v grub-mkconfig &>/dev/null; then
				sudo grub-mkconfig -o /boot/grub/grub.cfg
			else
				log_warn "Could not update GRUB automatically. Run 'update-grub' or equivalent manually."
			fi
		fi
	fi

	# Enable service
	if command -v systemctl &>/dev/null; then
		sudo systemctl enable apparmor
		sudo systemctl start apparmor || log_warn "AppArmor service started but kernel module may need reboot."
	fi
}

manage_apparmor() {
	log_info "=== Application Confinement (AppArmor) ==="

	local aa_active=0
	if command -v aa-status &>/dev/null; then
		if sudo aa-status --enabled 2>/dev/null; then
			aa_active=1
		fi
	fi

	if [[ $aa_active -eq 0 ]]; then
		log_warn "AppArmor is NOT active."
		echo "1) Install and Configure AppArmor"
		echo "2) Back"
		read -p "Select Option: " choice

		if [[ "$choice" == "1" ]]; then
			install_apparmor_tools
			enable_apparmor_grub
			log_warn "Configuration applied. SYSTEM REBOOT REQUIRED to enable AppArmor."
		fi
		return
	fi

	# AppArmor is active, show management menu
	echo "Status: Active"
	# Show summary count if available, otherwise full status might be too long so just head
	sudo aa-status 2>/dev/null | head -n 5 || echo "Status check failed"

	echo ""
	echo "1) View Detailed Status"
	echo "2) Set All Profiles to Complain Mode (Safe/Learning)"
	echo "3) Set All Profiles to Enforce Mode (Strict)"
	echo "4) Reload Profiles"
	echo "5) Back"

	read -p "Select Option: " choice
	case $choice in
	1)
		sudo aa-status
		;;
	2)
		log_info "Switching all profiles to COMPLAIN mode..."
		sudo aa-complain /etc/apparmor.d/*
		;;
	3)
		safety_check "Switching to ENFORCE mode can crash apps if profiles are not perfect."
		log_info "Switching all profiles to ENFORCE mode..."
		sudo aa-enforce /etc/apparmor.d/*
		;;
	4)
		log_info "Reloading AppArmor service..."
		if command -v systemctl &>/dev/null; then
			sudo systemctl reload apparmor
		else
			sudo service apparmor reload
		fi
		;;
	*) ;;
	esac
}
