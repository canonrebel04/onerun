#!/bin/bash

# Platform hardening script
# Disables network redirects, kernel module loading, and NFS/RPC services.

# Check for RedHat-based system before trying to use yum
if [[ -f /etc/redhat-release ]]; then
	echo "RedHat-based system detected. Installing kernel-modules-extra..."
	sudo yum install -y kernel-modules-extra
else
	echo "Not a RedHat-based system. Skipping 'yum install kernel-modules-extra'."
	# On Arch/CachyOS, kernel modules are usually part of the main kernel package (linux) or linux-headers.
fi

# Hardening sysctl
echo "Applying sysctl hardening..."
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
# Note: Disabling module loading is very aggressive and might break things if done too early or if needed modules aren't loaded yet.
# sudo sysctl -w kernel.modules_disabled=1

# Services to stop and disable
SERVICES=(
	"rpcbind.service"
	"nfs-server.service"
	"rpcbind.socket"
	"nfs-lock.service"
	"nfs-idmap.service"
	"rpc-statd.service"
	"rpc-statd-notify.service"
	"rpcbind.target"
	"rpc-gssd.service"
	"rpc-svcgssd.service"
	"rpc-gssd.socket"
	"rpc-svcgssd.socket"
)

echo "Stopping and disabling NFS/RPC services..."

for service in "${SERVICES[@]}"; do
	if systemctl list-unit-files "${service}" &>/dev/null; then
		echo "Processing ${service}..."
		sudo systemctl stop "${service}" 2>/dev/null || true
		sudo systemctl disable "${service}" 2>/dev/null || true
	else
		echo "Service ${service} not found, skipping."
	fi
done

echo "Hardening complete."
