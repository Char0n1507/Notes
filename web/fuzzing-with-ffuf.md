# Fuzzing with ffuf

```sh
# Directory fuzzing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://SERVER_IP:PORT/FUZZ

# Extension fuzzing. We use index to test extensions as it is always present
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt -u http://SERVER_IP:PORT/blog/indexFUZZ

# Page fuzzing. Only after extension fuzzing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php

# Recursive fuzzing
ffuf -w <wordlist> -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e <.extension> -v

# Subdomain fuzzing
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.DOMAIN/

# Vhost fuzzing
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://DOMAIN:PORT/ -H 'Host: FUZZ.DOMAIN'

# Fuzzing parameters - GET
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://DOMAIN:PORT/admin/admin.php?FUZZ=key -fs <size>

# Fuzzing parameters - POST. PHP POST data can only accept application/x-www-form-urlencoded
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://DOMAIN:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs <size>

# Value fuzzing - Only after discovering a parameter (ex : id)
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt -u http://DOMAIN:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs <size>
```
