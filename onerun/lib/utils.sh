#!/bin/bash

# Logging configuration
LOG_DIR="${LOG_DIR:-./logs}"
mkdir -p "${LOG_DIR}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_message() {
	local level="$1"
	local message="$2"
	local timestamp
	timestamp=$(date "+%Y-%m-%d %H:%M:%S")
	echo -e "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_DIR}/onerun.log"
}

log_info() {
	log_message "INFO" "${GREEN}${1}${NC}"
}

log_success() {
	log_message "SUCCESS" "${GREEN}${1}${NC}"
}

log_warn() {
	log_message "WARN" "${YELLOW}${1}${NC}"
}

log_error() {
	log_message "ERROR" "${RED}${1}${NC}"
}

# Logs a command execution (legacy compatibility)
# Logs a command execution (legacy compatibility)
log_command() {
	local now
	now=$(date "+%H-%M")
	echo "At ${now} the user ${USER} ran: $1" >>"${LOG_DIR}/ran_commands.txt"
}

handle_error() {
	if command -v dialog &>/dev/null; then
		dialog --msgbox "$1" 10 40
	else
		log_error "$1"
	fi
}

# Variable to control dry-run mode
DRY_RUN=${DRY_RUN:-0}

# Safety check
# Usage: safety_check "Description of action"
safety_check() {
	if [[ ${FORCE} != "1" ]]; then
		log_warn "Safety Check: $1"
		log_warn "This is a potentially destructive action."
		read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
		echo
		if [[ ! ${REPLY} =~ ^[Yy]$ ]]; then
			log_info "Aborted by user."
			return 1
		fi
	fi
	return 0
}
