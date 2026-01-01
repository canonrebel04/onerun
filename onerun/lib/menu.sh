#!/bin/bash

change_preset() {
	echo "Current Preset: ${PRESET}"
	PS3="Select Preset: "
	select p in "Standard (Default)" "Hardened (Destructive)" "Minimal (Audit Only)" "Back"; do
		case $p in
		"Standard (Default)")
			export PRESET="standard"
			export ENABLE_SSH=true
			break
			;;
		"Hardened (Destructive)")
			export PRESET="hardened"
			export ENABLE_SSH=false
			break
			;;
		"Minimal (Audit Only)")
			export PRESET="minimal"
			export ENABLE_SSH=true
			break
			;;
		"Back") break ;;
		*) echo "Invalid option." ;;
		esac
	done
	log_info "Switched to preset: ${PRESET}"
}

security_tools_menu() {
	while true; do
		echo "=========================================="
		echo "   ONERUN - Security Tools Manager"
		echo "=========================================="
		PS3="Select Tool: "
		select opt in \
			"Firewall (UFW)" \
			"Intrusion Prevention (Fail2Ban)" \
			"Rootkit Scan (RKHunter)" \
			"Deep Audit (Lynis)" \
			"System Auditing (Auditd)" \
			"USB Device Control (USBGuard)" \
			"Application Confinement (AppArmor)" \
			"Compliance & Benchmarks (CIS)" \
			"Back"; do
			
			case ${opt} in
			"Firewall (UFW)")
				manage_firewall
				break
				;;
			"Intrusion Prevention (Fail2Ban)")
				manage_fail2ban
				break
				;;
			"Rootkit Scan (RKHunter)")
				run_rkhunter
				break
				;;
			"Deep Audit (Lynis)")
				run_lynis
				break
				;;
			"System Auditing (Auditd)")
				manage_auditd
				break
				;;
			"USB Device Control (USBGuard)")
				manage_usbguard
				break
				;;
			"Application Confinement (AppArmor)")
				manage_apparmor
				break
				;;
			"Compliance & Benchmarks (CIS)")
				manage_compliance
				break
				;;
			"Back")
				return
				;;
			*) echo "Invalid option." ;;
			esac
		done
		echo
		read -r -p "Press Enter to continue..."
	done
}

main_menu() {
	while true; do
		echo "=========================================="
		echo "   ONERUN - System Hardening Tool"
		echo "   OS: ${OS_TYPE}"
		echo "   Package Manager: ${PKG_MANAGER}"
		echo "   Active Preset: ${PRESET}"
		echo "   SSH Enabled: ${ENABLE_SSH}"
		echo "=========================================="

		PS3="Select Option: "
		select opt in \
			"Select Hardening Preset" \
			"Install/Verify Security Tools" \
			"Apply Hardening (Based on Preset)" \
			"Remove SSH & Telnet (Explicit)" \
			"Change ALL User Passwords" \
			"Find Users Without Passwords" \
			"System Audit (Ports/Services)" \
			"Find SUID Files" \
			"Check Cronjobs" \
			"Network Hardening (Sysctl)" \
			"Secure SSH Config (Keys Only)" \
			"Backup Menu" \
			"Exit"; do

			case ${opt} in
			"Select Hardening Preset")
				change_preset
				break
				;;
			"Install/Verify Security Tools")
				security_tools_menu
				break
				;;
			"Apply Hardening (Based on Preset)")
				if [[ "${PRESET}" == "hardened" ]]; then
					remove_ssh
				else
					log_info "Standard/Minimal preset active. Removing Telnet only..."
					remove_package "telnet" || true
				fi
				change_all_pass
				users_no_pass
				motd
				break
				;;
			"Remove SSH & Telnet (Explicit)")
				force_remove_ssh
				break
				;;
			"Change ALL User Passwords")
				change_all_pass
				break
				;;
			"Find Users Without Passwords")
				users_no_pass
				break
				;;
			"System Audit (Ports/Services)")
				service_status
				potentially_malicious_services
				break
				;;
			"Find SUID Files")
				find_setuid
				break
				;;
			"Check Cronjobs")
				cron_check
				break
				;;
			"Network Hardening (Sysctl)")
				apply_sysctl_hardening
				break
				;;
			"Secure SSH Config (Keys Only)")
				secure_ssh_config
				break
				;;
			"Backup Menu")
				backup_menu
				break
				;;
			"Exit")
				echo "Exiting."
				exit 0
				;;
			*)
				echo "Invalid option."
				;;
			esac
		done

		echo
		read -r -p "Press Enter to continue..."
	done
}
