# 22 - SSH

### Service enumeration

#### Fingerprinting

```sh
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <IP>
```

#### Change the authentication method

```sh
# Will output the available auth types
ssh -v <USER>@<IP>  

# Change the auth method (ex : force password auth)  
ssh -v <USER>@<IP> -o PreferredAuthentications=<METHOD>
```

### Brute force

```sh
hydra -l <USER> -P <WORDLIST> ssh://<IP>
```
