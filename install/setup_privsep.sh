#!/bin/bash
if [[ $EUID -ne 0 ]]; then
	echo "Run it as root"
	exit 1
fi
mkdir /var/empty
chown root:sys /var/empty
chmod 755 /var/empty
groupadd sshd
useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd
