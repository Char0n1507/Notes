# Network Traffic

Plaintext protocols (like `HTTP`, `FTP`, `SNMP`, `SMTP`) are widely used within organizations. Being able to capture and parse that traffic could offer attackers valuable information like sensitive files, passwords or hashes

### Dumping secrets

```sh
# Dump from a pcap file
https://github.com/lgandx/PCredz
./Pcredz -f <PCAP_FILE> -t -v
```
