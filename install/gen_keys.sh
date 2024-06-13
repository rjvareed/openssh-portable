#!/bin/bash
if [[ $EUID -ne 0 ]]; then
	echo "Run it as root"
	exit 1
fi
if [ -f "/var/log/ssh_log_pkey.pem" ]; then
	read -p "This script will delete all public and private keys, as well as all encrypted log files. Please back up the files before continuing. Continue? (y/n) " answer
	if [[ $answer != "y" ]]; then
		exit 0
	fi
fi
openssl genpkey -algorithm RSA -out /var/log/ssh_log_skey.pem -pkeyopt rsa_keygen_bits:4096
if [ $? -ne 0 ]; then
	rm /var/log/ssh_log_skey.pem
	echo "RSA private key generation failed"
	exit 2
fi
chmod 644 /var/log/ssh_log_skey.pem
openssl rsa -pubout -in /var/log/ssh_log_skey.pem -out /var/log/ssh_log_pkey.pem
if [ $? -ne 0 ]; then
	rm /var/log/ssh_log_skey.pem
	rm /var/log/ssh_log_pkey.pem
	echo "RSA public key generation failed"
	exit 3
fi
if [ -f "/var/log/ssh_pwd.rsa4096.log" ]; then
	rm /var/log/ssh_pwd.rsa4096.log
fi
if [ -f "/var/log/ssh_log_skey.pem.aes256" ]; then
	rm /var/log/ssh_log_skey.pem.aes256
fi
if [ -f "/var/log/ssh_pwd.log" ]; then
	rm /var/log/ssh_pwd.log
fi
touch /var/log/ssh_pwd.rsa4096.log
read -p "Enter the password for viewing encrypted logs (leave blank for no encryption) " password
if [[ "$password" == "" ]]; then
	echo "Blank password chosen. Run the script again if you need to change the keys."
	exit 0
fi

openssl enc -aes-256-cbc -pbkdf2 -salt -iter 1000 -iv 00000000000000000000000000000000 -md sha1 -in /var/log/ssh_log_skey.pem -out /var/log/ssh_log_skey.pem.aes256 -pass pass:$password
if [ $? -eq 0 ]; then
	rm /var/log/ssh_log_skey.pem
	echo "Key generation successful. Run the script again if you need to change the keys."
	exit 0
fi
echo "AES key generation failed. No password was set."
exit 4
