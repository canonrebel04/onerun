#!/bin/bash

# Audit and Reconnaissance functions

find_setuid() {
	log_info "Searching for setuid files..."
	find / -perm -u=s -type f -exec ls -la {} + 2>/dev/null
}

cron_check() {
	log_info "Checking user crontabs..."
	while read -r user; do
		if crontab -l -u "${user}" &>/dev/null; then
			echo "--------------------------------"
			echo "User: ${user}"
			crontab -l -u "${user}"
			echo "--------------------------------"
		fi
	done < <(cut -d: -f1 /etc/passwd || true)
}

potentially_malicious_services() {
	log_info "Checking for potentially malicious services..."
	local services=("nc" "netcat" "ncat" "hydra" "john" "nikto" "wireshark" "tcpdump")

	for s in "${services[@]}"; do
		if command -v "${s}" &>/dev/null; then
			log_warn "FOUND POTENTIAL TOOL: ${s}"
		fi
	done
}

service_status() {
	log_info "Listing running services..."
	if command -v systemctl &>/dev/null; then
		systemctl list-units --type=service --state=running
	else
		service --status-all | grep '\[ + \]' || true
	fi
}

mysql_user_check() {
	if command -v mysql &>/dev/null; then
		log_info "Checking MySQL users..."
		mysql -u root -p -e "SELECT User, Host, authentication_string FROM mysql.user;" || log_error "Failed to query MySQL"
	else
		log_info "MySQL not installed."
	fi
}
