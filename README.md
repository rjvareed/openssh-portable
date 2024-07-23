# What is this?
This is a custom version of the OpenSSH suite for Linux, forked from OpenBSD's Portable OpenSSH implementation. It features a few slight code modifications, namely to `auth-passwd.c` which uses code from a new header file I made called `log_pwd.h`. I also included a new program that will allow you to easily view the logs, called `view-ssh-logs`. Its source code lives in `view-ssh-logs.c`, a utility I made to decrypt and display the logs.

I made this because I noticed a lot of ssh login attempts to my network's Raspberry Pi after opening it to the internet and I was curious to see which passwords were being used. These passwords are trivial to extract as they are stored during the execution of `sshd-session` in an Authctxt structure, located within a larger ssh structure. This structure also includes the username, ip address, source ports, and other useful information that can be logged. By default, the logs are stored in plaintext in the file `/var/log/ssh_pwd.log`. Automated encryption of the logs is optional and I included a script to set it up.

# Log structure
The log format is: `<date and time> <ip address> <username (truncated to 1024 characters)> <password (truncated to 1024 characters)>`
I included a program in the suite that will allow you to easily view these logs, simply run `view-ssh-logs` and it will prompt you for a password if they are encrypted.
Here's a snippet of the logs, taken from real data:
```
Jul 23 07:50:57 183.81.169.238 root:123456
Jul 23 07:51:01 183.81.169.238 root:123123
Jul 23 07:51:05 183.81.169.238 root:test
Jul 23 07:51:09 183.81.169.238 root:123456789
Jul 23 07:58:22 213.109.202.127 installer:installer
Jul 23 08:04:47 193.201.9.156 admin:12345
Jul 23 08:48:39 85.209.11.227 root:admin
Jul 23 08:50:05 213.109.202.127 user:123
Jul 23 09:03:42 193.201.9.156 ftp:ftp
Jul 23 09:40:20 213.109.202.127 ubnt:admin
```

# Optional log encryption
Since the logs store all login attempts (including successful attempts), it seems reasonable to encrypt them. The program does this using RSA-4096 with OAEP padding. It reads a 4096 bit RSA public key stored in `/var/log/ssh_log_pkey.pem` and uses this to encrypt each 512 byte block, which is then appended to the encrypted log file `/var/log/ssh_pwd.rsa4096.log`. The corresponding RSA private key .pem file is called `/var/log/ssh_log_skey.pem.aes256` and is encrypted with AES-256 in CBC mode using the IV "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0". The AES-256 key is derived from a password using PBKDF2 with 1000 SHA1 iterations. 

`view-ssh-logs` will look for and attempt to decrypt `/var/log/ssh_log_skey.pem.aes256` to get the RSA private key. If it finds this file it will prompt you for a password. If the file doesn't exist then it will look for the plaintext private key .pem file, `/var/log/ssh_log_skey.pem`. It will use the RSA private key to decrypt the log file and display it to stdout. If none of these files exist it means no encryption is set up so it will simply display the plaintext file `/var/log/ssh_pwd.log`. This encryption can be easily set up using the script I provided, `gen_keys.sh`. This script is run in the "Building and installing section". It is recommended to use tr with the output of view-ssh-logs or to save its output to a file as some of the unprintable characters can mess up your terminal. Additionally, it takes a long time to decrypt the logs so I usually use it with the -l option, which will display the last few records:
`view-ssh-logs -l 50` displays the last 50 records.

# Raspbian setup / pentesting
To set this up on my network's Raspberry Pi running Raspbian, I simply ran `sudo apt remove openssh-server` and `sudo apt install autoconf libssl-dev` then proceeded with the commands listed in the "Building and Installing:" section of this readme. This software is actually running right now on my personal Raspberry Pi hosted at aaaabbbccd.com. Please feel free to log in there. You can send a message to me with `ssh hello@aaaabbbccd.com`. I tried to guard against buffer overflows and various other security vulnerabilities, but if you are able to find something or are able to otherwise get into my Raspberry Pi please shoot me an email.

# Building and installing:
```
git clone https://github.com/rjvareed/openssh-portable
cd openssh-portable
autoreconf
./configure
make
sudo install/setup_privsep.sh
sudo install/gen_keys.sh
sudo make install
sudo cp install/ssh.service /lib/systemd/system/ssh.service
sudo systemctl enable ssh.service
sudo systemctl start ssh.service
```

# Uninstalling:
```
sudo make uninstallall
sudo systemctl stop ssh.service
sudo systemctl disable ssh.service
```
Let me know if you encounter any problems.
