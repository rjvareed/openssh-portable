# What is this?
This is a custom version of the OpenSSH suite for Linux, forked from OpenBSD's Portable OpenSSH implementation. It features a few slight code modifications, namely to `auth-passwd.c` which uses code from a new header file I made called `log_pwd.h`. I also included a new program that will allow you to easily view the logs, called `view-ssh-logs`. Its source code lives in `view-ssh-logs.c`, a utility I made to decrypt and display the logs.

<<<<<<< HEAD
I made this because I noticed a lot of ssh login attempts to my network's Raspberry Pi after opening it to the internet and I was curious to see which passwords were being used. These passwords are trivial to extract as they are stored during the execution of `sshd-session` in an Authctxt structure, located within a larger ssh structure. This structure also includes the username, ip address, source ports, and other useful information that can be logged. By default, the logs are stored in plaintext in the file `/var/log/ssh_pwd.log`. Automated encryption of the logs is optional and I included a script to set it up.
=======
[![C/C++ CI](https://github.com/openssh/openssh-portable/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/openssh/openssh-portable/actions/workflows/c-cpp.yml)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/openssh.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:openssh)
[![Coverity Status](https://scan.coverity.com/projects/21341/badge.svg)](https://scan.coverity.com/projects/openssh-portable)

OpenSSH is a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client ``ssh`` and server ``sshd``, file transfer utilities ``scp`` and ``sftp`` as well as tools for key generation (``ssh-keygen``), run-time key storage (``ssh-agent``) and a number of supporting programs.

This is a port of OpenBSD's [OpenSSH](https://openssh.com) to most Unix-like operating systems, including Linux, OS X and Cygwin. Portable OpenSSH polyfills OpenBSD APIs that are not available elsewhere, adds sshd sandboxing for more operating systems and includes support for OS-native authentication and auditing (e.g. using PAM).

## Documentation

The official documentation for OpenSSH are the man pages for each tool:

* [ssh(1)](https://man.openbsd.org/ssh.1)
* [sshd(8)](https://man.openbsd.org/sshd.8)
* [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [scp(1)](https://man.openbsd.org/scp.1)
* [sftp(1)](https://man.openbsd.org/sftp.1)
* [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Stable Releases

Stable release tarballs are available from a number of [download mirrors](https://www.openssh.com/portable.html#downloads). We recommend the use of a stable release for most users. Please read the [release notes](https://www.openssh.com/releasenotes.html) for details of recent changes and potential incompatibilities.

## Building Portable OpenSSH

### Dependencies

Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used.  OpenSSH may be built without either of these, but the resulting binaries will have only a subset of the cryptographic algorithms normally available.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies and will be enabled automatically if they are found.

In addition, certain platforms and build-time options may require additional dependencies; see README.platform for details about your platform.

### Building a release

Release tarballs and release branches in git include a pre-built copy of the ``configure`` script and may be built using:
>>>>>>> upstream/master

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

<<<<<<< HEAD
# Raspbian setup / pentesting
To set this up on my network's Raspberry Pi running Raspbian, I simply ran `sudo apt remove openssh-server` and `sudo apt install autoconf libssl-dev` then proceeded with the commands listed in the "Building and Installing:" section of this readme. This software is actually running right now on my personal Raspberry Pi hosted at aaaabbbccd.com. Please feel free to log in there. You can send a message to me with `ssh hello@aaaabbbccd.com`. I tried to guard against buffer overflows and various other security vulnerabilities, but if you are able to find something or are able to otherwise get into my Raspberry Pi please shoot me an email.
=======
If building from the git master branch, you'll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the ``configure`` script. The following commands will check out and build portable OpenSSH from git:
>>>>>>> upstream/master

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
