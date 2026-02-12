# Password Policy / Time

### Policies

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Use crendentials if known
nxc smb <IP> -u '' -p '' --pass-pol

rpcclient -U "" -N <IP>
getdompwinfo

ldapsearch -H <IP>-x -b "DC=<DC>,DC=<DC>" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

enum4linux-ng -P <IP> -oA <OUTPUT_FILE>
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# From cmd.exe
net account
net account /domain

# From powershell
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
import-module .\PowerView.ps1
Get-DomainPolicy
```
{% endtab %}
{% endtabs %}

### Set time

Analyzing the Password Set times is incredibly important when performing password sprays.\
Organizations are much more likely to find an automated password spray across all\
accounts than at a few guesses towards a small group of accounts.

* If you see a several passwords set at the same time , this indicates they were set\
  by the Help Desk and may be the same. Because of Password Lockout Policies, you\
  may not be able to exceed four failed passwords in fifteen minutes. However, if you\
  think the password is the same across 20 accounts, for one user, you can guess\
  passwords along the line of "Password2020" for a different use, you can use the\
  company name like "Freight2020!".
* Additionally, if you see the password was set in July of 2019; then you can normally\
  exclude "2020" from your password guessing and probably shouldn't guess variations\
  that wouldn't make sense, such as "Winter2019."
* If you see an old password that was set 2 years ago , chances are this password\
  is weak and also one of the first accounts I would recommend guessing the password\
  to before launching a large Password Spray.
* In most organizations, administrators have multiple accounts. If you see the\
  administrator changing his "user account" around the same time as his "Administrator\
  Account", they are highly likely to use the same password for both accounts.

```shellscript
# Display all passwords set time
Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | Sort-Object -Property pwdlastset

# Show passwords set before a certain date 
Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | where { $_.pwdlastset -lt (Get-Date).addDays(-90) }
```
