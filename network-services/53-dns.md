# 53 - DNS

### Service enumeration

#### Machine host name

{% tabs %}
{% tab title="nslookup" %}
```shellscript
nslookup
> server <DNS_SERVER_IP>
> <MACHINE_IP>
```
{% endtab %}

{% tab title="dig" %}
```shellscript
dig -x @<DNS_SERVER_IP> <MACHINE_IP>
```
{% endtab %}
{% endtabs %}

#### Any record

```sh
dig any <DOMAIN> @<DNS_SERVER_IP>
```

#### Zone transfers

The default configuration for DNS on Linux is to only listen on UDP. The one piece of DNS that requires TCP is zone transfers.

<mark style="background-color:red;">When seeing TCP port 53 open on Linux ⇒ think zone transfers</mark>

```sh
# Try without a domain
dig axfr @<DNS_SERVER_IP>

# With domain
dig axfr <DOMAIN> @<DNS_SERVER_IP>

# Will try a zone transfer against every authoritative name server
https://github.com/mschwager/fierce
fierce --domain <DOMAIN> --dns-servers <DNS_SERVER_IP>
```

#### Subdomain brute force

```sh
for sub in $(cat /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.<DOMAIN> @<DNS_SERVER_IP> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
dnsenum --dnsserver <DNS_SERVER_IP> --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt <DOMAIN>

https://github.com/projectdiscovery/subfinder
./subfinder -d <DOMAIN> -v

git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "<DNS_SERVER_IP>" > ./resolvers.txt
./subbrute <DOMAIN> -s ./names.txt -r ./resolvers.txt
```
