# Information Gathering

### Environment Enumeration

#### Situation awareness

```shellscript
# What user are we running as
whoami

# What groups does our user belong to
id

# What is the machine named ? Can we gather anything from the naming convention ?
hostname

# What subnet did we land in ? Are there any others ?
ip a
cat /etc/hosts

# Can our user run anything with sudo ? 
sudo -l

# What is the OS and its version
cat /etc/os-release

# Check our current user's path
echo $PATH

# Check the environment variables => we could find sensitive stuff such as passwords
env

# Check the kernel version 
uname -a 
cat /proc/version

# CPU type and version
lscpu

# What shells exist on the system ? 
cat /etc/shells

# Check for drives or shares on the system => maybe we can discover a new share to mount
lsblk

# Find informations about any printers attached to the system => if there are active 
# print jobs, we can gain access to them
lpstat

# Check for mounted and unmounted drives
cat /etc/fstab

# Check the routing table => what other networks are available via which interface
route
netstat -rn

# If the host is in a domain environment, check for internal DNS
cat /etc/resolv.conf

# Check the ARP table to see what other hosts the system has been communicating with
arp -a

# Find writeable directories
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

# Find writeable files
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

#### Users

```shellscript
# Existing users 
cat /etc/passwd

# Make a user list from /etc/passwd
cat /etc/passwd | cut -f1 -d:

# Which users have a login shell 
grep "sh$" /etc/passwd

# Which users have a home dir
ls /home

# Look if .bash_history is readable, same for .ssh

# Search for files ending in .conf and .config
```

#### Groups

```shellscript
# Existing groups
cat /etc/groups

# List members of a group 
getent group <GROUP>
```

#### File system

```shellscript
# Mounted file system
df -h

# Unmounted file system
cat /etc/fstab | grep -v "#" | column -t

# All hidden files
find / -type f -name ".*" -exec ls -l {} \\; 2>/dev/null | grep <USER>

# All hidden directories
find / -type d -name ".*" -ls 2>/dev/null

# Temporary files 
ls -l /tmp /var/tmp /dev/shm
```

### Linux Services & Internals Enumeration

#### Internals

```shellscript
# Users last login 
lastlog

# Logged in users
w 

# Check a user bash history
history

# Find history files created by scripts
find / -type f \\( -name *_hist -o -name *_history \\) -exec ls -l {} \\; 2>/dev/null

# Check for cron jobs
ls -la /etc/cron.daily

# Get information on processes 
find /proc -name cmdline -exec cat {} \\; 2>/dev/null | tr " " "\\n"
```

#### Services

If it is a slightly older Linux system, the likelihood increases that we can find installed packages that may already have at least one vulnerability.

```shellscript
# Check installed packages 
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

# Check sudo version
sudo -V

# It can happen that no packages are installed on the system but compiled binaries 
# => Then check GTFObins
ls -l /bin /usr/bin/ /usr/sbin/

# Compare the existing binaries with GTFObins to see which to investigate
for i in $(curl -s <https://gtfobins.github.io/> | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

# Find config files 
find / -type f \\( -name *.conf -o -name *.config \\) -exec ls -l {} \\; 2>/dev/null

# Check for scripts 
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\\|snap\\|share"

# Check running services by user
# if it is a script created by the administrator in his path and whose rights have not 
# been restricted, we can run it without going into the root directory
ps aux | grep <USER>
```

### **Credential Hunting**

```shellscript
# Look for passwords in file recursively
grep -ir 'password'

# Find config files
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```
