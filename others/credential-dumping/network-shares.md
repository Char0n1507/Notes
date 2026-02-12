# Network Shares

In organization networks, it is common to find passwords in random files (logs, config files, personal documents, Office documents, ...)

### Dumping secrets

{% tabs %}
{% tab title="Snaffler" %}
```sh
# Basic search
https://github.com/SnaffCon/Snaffler
Snaffler.exe -s

# Snaffle all the computers in the domain
Snaffler.exe -d domain.local -c  -s

# Snaffle specific computers
Snaffler.exe -n computer1,computer2 -s

# Snaffle a specific directory
Snaffler.exe -i C:\ -s
```
{% endtab %}

{% tab title="Manspider" %}
```sh
# From Linux
https://github.com/blacklanternsecurity/MANSPIDER
manspider.py --threads 50 <IP> -d <DOMAIN> -u <USER> -p <PASSWORD> -c "STRING_TO_LOOK_FOR"
```
{% endtab %}

{% tab title="Netexec" %}
```sh
# Outputs all available files in the given share
nxc smb <IP> -u <USER> -p <PASSWORD> -M spider_plus --share '<SHARE>'

nxc smb <IP> -u <USER> -p '<PASS>' --spider <SHARE> --content --pattern "<STRING_TO_LOOK_FOR>"
```
{% endtab %}
{% endtabs %}
