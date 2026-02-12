# 21 - FTP

### Service enumeration <a href="#service-enumeration" id="service-enumeration"></a>

#### Scan

```sh
nmap -p21 --script ftp-* <IP>
```

#### Banner grabbing

```sh
nc -nv <IP> 21
telnet <IP> 21
```

#### Service interaction

```sh
ftp <IP> 21

# If SSL/TLS
openssl s_client -connect <IP>:<PORT> -starttls ftp    
```

### Brute force

```sh
hydra -l <USER> -P <WORDLIST> ftp://<IP>
```

### Bounce attack

Network attack that uses FTP servers to deliver outbound traffic to another device on the network

Consider we are targeting an FTP Server `FTP_DMZ` exposed to the internet. Another device within the same network, `Internal_DMZ`, is not exposed to the internet. We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ` using the FTP Bounce attack and obtain information about the server's open ports

```sh
nmap -Pn -v -n -p- -b anonymous:password@<FTP_MACHINE_IP> <INTERNAL_IP>
```
