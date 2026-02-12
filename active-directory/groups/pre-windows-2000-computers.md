# Pre-Windows 2000 Computers

When a new computer account is configured as "`pre-Windows 2000 computer`", its password is set based on its name (i.e. lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated.

Once an authentication occurs for a `pre-Windows 2000` computer, according to [TrustedSec's blogpost](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/), its password will usually need to be changed.

### Enumeration

{% tabs %}
{% tab title="Netexec" %}
```shellscript
nxc ldap <DC> -u <USER> -p '<PASSWORD>' -M pre2k
```
{% endtab %}

{% tab title="Pre2k" %}
```shellscript
https://github.com/garrettfoster13/pre2k
pre2k auth -u <USER> -p '<PASSWORD>' -d <DOMAIN> -dc-ip <DC>
```
{% endtab %}

{% tab title="Ldap" %}
```shellscript
ldapsearch-ad -l <DC> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> -t search -s '(&(userAccountControl=4128)(logonCount=0))' | grep "sAMAccountName" | awk '{print $4}'
```
{% endtab %}
{% endtabs %}
