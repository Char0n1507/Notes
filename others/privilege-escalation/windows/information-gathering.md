# Information Gathering

### Situational Awareness

#### Network information

```shellscript
# Interfaces, IP addresses, DNS information
ipconfig /all

# ARP table => see which hosts the current machine has been communicating with
arp -a

# View routing tables
route print
```

#### Enumerating protections

Most modern environments have some sort of anti-virus or Endpoint Detection and Response (EDR) service running to monitor, alert on, and block threats proactively. These tools may interfere with the enumeration process. They will very likely present some sort of challenge during the privilege escalation process, especially if we are using some kind of public PoC exploit or tool. Enumerating protections in place will help us ensure that we are using methods that are not being blocked or detected and will help us if we have to craft custom payloads or modify tools before compiling them.

```shellscript
# Checlk Windows Defender status => look for AntivirusEnabled
Get-MpComputerStatus

# List AppLocker rules => used for application whitelisting 
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker Policy
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\\Windows\\System32\\cmd.exe -User Everyone
```

### Initial Enumeration

#### System information

```shellscript
# Check running processes => see if non standard processes are running
tasklist /svc

# Display environment variables
set

# View detailed configuration information => can tell us the OS version, if it is a VM
# and also show the last hotfixes installed => worth to google the hotfix KB to have
# an estimation of the date the system was patched for the last time
systeminfo

# Windows version
[environment]::OSVersion.Version
[System.Environment]::OSVersion.Version

# View last hotfixes if not displayeds by systeminfo 
wmic qfe
Get-HotFix | ft -AutoSize    # With powershell

# Check what programs are installed => Run LaZagne to check if stored credentials for 
# those applications are installed. Also, some programs may be installed and running as 
# a service that is vulnerable.
wmic product get name
Get-WmiObject -Class Win32_Product |  select Name, Version    # With Powershell

# Display running processes (eq to ss -tulpn)
netstat -ano
```

#### User & Group information

```shellscript
# Check logged-in users
query user

# Check current user
echo %USERNAME%

# Current user privileges
whoami /priv

# Current user group information
whoami /groups

# Get all users on the system 
net user

# Get all groups on the system
net localgroup

# Check details about a group
net localgroup "<GROUP>"

# Get password policy & other account informations
net accounts
```

#### Communication with Processes

```shellscript
# Check what ports are open locally => get the PID
netstat -ano

# Check what service is running on the corresponding port
tasklist /svc | find "<PID>"

# List named pipes
pipelist.exe /accepteula
gci \\.\pipe\    # Powershell

# Reviewing named pipe permissions
accesschk.exe /accepteula \pipe\lsass -v

# Check all pipes with write access => is dangerous if anybody has it
accesschk.exe -w \pipe\* -v
```
