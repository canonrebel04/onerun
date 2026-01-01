#!/bin/bash

BACKUP_ROOT="${BACKUP_ROOT:-./backups}"
mkdir -p "${BACKUP_ROOT}"

perform_backup() {
	local name="$1"
	shift
	local paths=("$@")

	local timestamp
	timestamp=$(date "+%H-%M")
	local dest="${BACKUP_ROOT}/${name}/${name}-backup-${timestamp}"

	mkdir -p "${dest}"
	log_info "Backing up ${name} to ${dest}..."

	for p in "${paths[@]}"; do
		if [[ -e ${p} ]]; then
			cp -r "${p}" "${dest}/"
			log_info "Copied ${p}"
		else
			log_warn "Path ${p} NOT found, skipping."
		fi
	done
}

backup_menu() {
	PS3="Select backup target: "
	select opt in "NGINX" "Apache" "MySQL" "SSH" "Exit"; do
		case ${opt} in
		"NGINX") perform_backup "nginx" "/etc/nginx" "/usr/share/nginx/html" ;;
		"Apache") perform_backup "apache" "/etc/apache2" "/var/www/html" ;;
		"MySQL")
			if command -v mysqldump &>/dev/null; then
				mkdir -p "${BACKUP_ROOT}/mysql"
				mysqldump --all-databases >"${BACKUP_ROOT}/mysql/dump-$(date +%s).sql"
				log_info "MySQL dumped."
			else
				log_error "mysqldump not found"
			fi
			;;
		"SSH") perform_backup "ssh" "/etc/ssh" "/root/.ssh" ;;
		"Exit") break ;;
		*) echo "Invalid" ;;
		esac
	done
}
