# Computers

### List computers

{% tabs %}
{% tab title="Linux" %}
```shellscript
nxc ldap <IP> -u <USER> -p <PASSWORD> --computers
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
net view

# Domain computers
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol
# Export the list to CSV
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol | Export-Csv .\<NAME>.csv -NoTypeInformation
net view /domain  
```
{% endtab %}
{% endtabs %}

### Finding exploitable machines

The following flags can be combined to help come up with attacks: \\

* `LastLogonTimeStamp` : This field exists to let administrators find stale machines. If this\
  field is 90 days old for a machine, it has not been turned on and is missing both\
  operating system and application patches. Due to this, administrators may want to\
  automatically disable machines upon this field hitting 90 days of age. Attackers can use\
  this field in combination with other fields such as Operating System or When Created\
  to identify targets.
* `OperatingSystem` : This lists the Operating System. The obvious attack path is to find a\
  Windows 7 box that is still active (LastLogonTimeStamp) and try attacks like Eternal\
  Blue. Even if Eternal Blue is not applicable, older versions of Windows are ideal spots\
  to work from as there are fewer logging/antivirus capabilities on older Windows. It's also\
  important to know the differences between flavors of Windows. For example, Windows\
  10 Enterprise is the only version that comes with "Credential Guard" (Prevents\
  Mimikatz from Stealing Passwords) Enabled by default. If you see Administrators\
  logging into Windows 10 Professional and Windows 10 Enterprise, the Professional box\
  should be targeted.
* `WhenCreated` : This field is created when a machine joins Active Directory. The older\
  the box is, the more likely it is to deviate from the "Standard Build." Old workstations\
  could have weaker local administration passwords, more local admins, vulnerable\
  software, more data, etc

### Computer attacks

```shellscript
# Check if any computer is configured to allow unconstrained delegation
Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol

# Check if any computer is configured to allow constrained delegation
Get-DomainComputer -TrustedToAuth | select -Property dnshostname,useraccountcontrol
```
