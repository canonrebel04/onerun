#!/bin/bash

# ONERUN - Main Orchestrator
# This script initializes the environment and launches the main menu.

set -e # Exit on error (safety)

# Locate directory
SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
cd "${SCRIPT_DIR}"

# Source Environment
if [[ -f "./onerun.env" ]]; then
	source ./onerun.env
fi

# Default Paths (if not in env)
LOG_DIR="${logpath:-./logs}"
export LOG_DIR

# Source Libraries
source ./lib/utils.sh
source ./lib/pkg.sh
source ./lib/hardening.sh
source ./lib/audit.sh
source ./lib/backup.sh
source ./lib/menu.sh
source ./lib/tools.sh
source ./lib/mac.sh
source ./lib/compliance.sh

# Argument Parsing
auto_mode=0
# Configuration Defaults
export PRESET="standard"     # standard, hardened, minimal
export ENABLE_SSH=true       # true (standard), false (hardened)
export FORCE=0

usage() {
	echo "Usage: $0 [OPTIONS]"
	echo "  -h, --help      Show this help"
	echo "  -f, --force     Skip safety prompts (DANGEROUS)"
	echo "  -a, --auto      Run recommended hardening immediately (No menu)"
	echo "  --preset [val]  Select hardening preset: standard (default), hardened, minimal"
	echo "  --keep-ssh      Force keep SSH enabled (overrides preset)"
}

while [[ $# -gt 0 ]]; do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	-f | --force) export FORCE=1 ;;
	-a | --auto) auto_mode=1 ;;
	--preset)
		shift
		if [[ "$1" =~ ^(standard|hardened|minimal)$ ]]; then
			export PRESET="$1"
		else
			echo "Invalid preset: $1. Must be standard, hardened, or minimal."
			exit 1
		fi
		;;
	--keep-ssh) export ENABLE_SSH=true ;;
	*)
		echo "Unknown option: $1"
		usage
		exit 1
		;;
	esac
	shift
done

# Apply Preset Configuration
case "${PRESET}" in
hardened)
	[[ "${ENABLE_SSH}" == "true" ]] || export ENABLE_SSH=false
	;;
minimal)
	export ENABLE_SSH=true
	;;
standard)
	export ENABLE_SSH=true
	;;
esac

# Initialize
log_info "Starting ONERUN..."

# Root check
if [[ ${EUID} -ne 0 ]]; then
	log_error "This script must be run as root."
	exit 1
fi

log_info "OS Detected: ${OS_TYPE}"
log_info "Package Manager: ${PKG_MANAGER}"
log_info "Active Preset: ${PRESET} (SSH Enabled: ${ENABLE_SSH})"

if [[ ${auto_mode} -eq 1 ]]; then
	log_info "Auto-mode enabled. Applying '${PRESET}' preset..."
	
	# Common Tasks
	init_passwords
	motd
	
	# Preset Logic
	if [[ "${PRESET}" == "hardened" ]]; then
		remove_ssh
	elif [[ "${PRESET}" == "standard" ]]; then
		# Standard removes telnet but keeps SSH
		log_info "Standard Mode: Ensuring Telnet is removed..."
		remove_package "telnet" || true
	fi
	
	exit 0
fi

# Launch Menu
main_menu
