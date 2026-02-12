# 161,162/UDP - SNMP

### Service enumeration

#### Scan

```sh
nmap --script "snmp* and not snmp-brute" <IP>
```

#### Community strings information

SNMP version `1` and `2c` does not require any authentication, we just need to give the tool a valid community string. Always try `public`

```sh
snmpwalk -v<VERSION> -c <COMMUNITY_STRING> <IP> -m all

# SNMP takes a long time to enumerate with snmpwalk. Use snmpbulkwalk to enumerate faster
# with threading
snmpbulkwalk -v<VERSION> -c <COMMUNITY_STRING> <IP> -m all
```

#### Brute force community strings

```sh
sudo apt install onesixtyone
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt <IP>
```

#### Brute force OIDs

```sh
# Brute force OIDs once we know the community string
sudo apt install braa
braa <community string>@<IP>:.1.3.6.*
```
