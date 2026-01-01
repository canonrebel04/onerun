#!/bin/bash

# Source utilities if not already sourced
if [ -z "${RED:-}" ]; then
	SCRIPT_PATH=$(readlink -f "$0")
	SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
	# Attempt to source from SCRIPT_DIR, then fallback to lib/utils.sh
	if ! source "${SCRIPT_DIR}/utils.sh"; then
		if ! source "./lib/utils.sh"; then
			echo "Error: Failed to source utils.sh from either '${SCRIPT_DIR}/utils.sh' or './lib/utils.sh'" >&2
			exit 1
		fi
	fi
fi

detect_os() {
	if [[ -f /etc/os-release ]]; then
		# Should return 'debian', 'ubuntu', 'fedora', 'centos', 'arch', etc.
		grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"' || true
	elif [[ -f /etc/redhat-release ]]; then
		echo "redhat"
	elif [[ -f /etc/debian_version ]]; then
		echo "debian"
	else
		echo "unknown"
	fi
}

OS_TYPE=$(detect_os)
PKG_MANAGER=""

case "${OS_TYPE}" in
debian | ubuntu | kali | parrot)
	PKG_MANAGER="apt-get"
	;;
fedora | centos | rhel | redhat | almalinux | rocky)
	if command -v dnf &>/dev/null; then
		PKG_MANAGER="dnf"
	else
		PKG_MANAGER="yum"
	fi
	;;
arch | cachyos | manjaro)
	PKG_MANAGER="pacman"
	;;
*)
	log_warn "Unknown OS: $OS_TYPE. Package management functions may fail."
	;;
esac

update_system() {
	log_info "Updating system packages..."
	case "${PKG_MANAGER}" in
	apt-get)
		export DEBIAN_FRONTEND=noninteractive
		sudo apt-get update -y && sudo apt-get upgrade -y
		;;
	dnf | yum)
		sudo "${PKG_MANAGER}" update -y
		;;
	pacman)
		sudo pacman -Syu --noconfirm
		;;
	*)
		log_error "Cannot update system: Unknown package manager"
		return 1
		;;
	esac
}

install_package() {
	local pkg="$1"
	log_info "Installing package: ${pkg}"

	case "${PKG_MANAGER}" in
	apt-get)
		export DEBIAN_FRONTEND=noninteractive
		sudo apt-get install -y "${pkg}"
		;;
	dnf | yum)
		sudo "${PKG_MANAGER}" install -y "${pkg}"
		;;
	pacman)
		sudo pacman -S --noconfirm "${pkg}"
		;;
	*)
		log_error "Cannot install ${pkg}: Unknown package manager"
		return 1
		;;
	esac
}

remove_package() {
	local pkg="$1"
	log_info "Removing package: ${pkg}"

	case "${PKG_MANAGER}" in
	apt-get)
		export DEBIAN_FRONTEND=noninteractive
		sudo apt-get remove -y "${pkg}"
		;;
	dnf | yum)
		sudo "${PKG_MANAGER}" remove -y "${pkg}"
		;;
	pacman)
		sudo pacman -Rns --noconfirm "${pkg}"
		;;
	*)
		log_error "Cannot remove ${pkg}: Unknown package manager"
		return 1
		;;
	esac
}