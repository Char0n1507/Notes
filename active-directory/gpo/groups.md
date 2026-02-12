# Groups

### List groups

{% tabs %}
{% tab title="Linux" %}
```shellscript
nxc smb <IP> -u <USER> -p <PASSWORD> --groups
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Domain groups
Get-ADGroup -Filter * | select name    # ActiveDirectory module
Get-DomainGroup | select name          # PowerView
net groups /domain                     # Cmd

# Local groups
Get-NetLocalGroup -ComputerName <COMPUTER> | select GroupName  # PowerView
wmic group list /format:list           # Wmic
net localgroup                         # Cmd
```
{% endtab %}
{% endtabs %}

### Information about a group

```shellscript
# Domain groups 
Get-ADGroup -Identity "<GROUP>"    # ActiveDirectory module
net group <GROUP> /domain          # Cmd

# Local group
net localgroup <GROUP>
```

### Group members

```shellscript
# Domain groups
Get-ADGroupMember -Identity "<GROUP>"                   # ActiveDirectory module
Get-DomainGroupMember -Identity "<GROUP>" -Recurse      # PowerView

# Local groups
Get-NetLocalGroupMember -ComputerName <COMPUTER>        # PowerView 
```

If we see a non-RID 500 user in the local administrators group, we can use the `Convert-`\
`SidToName` PowerView function to convert the SID and reveal the corresponding user. Then we can check to see if he is local admin anywhere else.

```ps1
# Reveal the non RID 500 local admin user
Convert-SidToName <SID>

# Check if the user is a local admin on any other computer
$sid = Convert-NameToSid <USER>
$computers = Get-DomainComputer -Properties dnshostname | select -ExpandProperty dnshostname
foreach ($line in $computers) {Get-NetLocalGroupMember -ComputerName $line | ? {$_.SID -eq $sid}}
```

### Protected Groups

```shellscript
# Powerview 
Get-DomainGroup -AdminCount    # List protected groups (high privileges)
```

Another important check is to look for any `managed security groups`. These groups have\
delegated non-administrators the right to add members to AD security groups and\
distribution groups and is set by modifying the `managedBy` attribute. This check looks to see\
if a group has a manager set and if the user can add users to the group. This could be useful\
for lateral movement by gaining us access to additional resources. First, let's take a look at\
the list of managed security groups.

```shellscript
# PowerView 
Find-ManagedSecurityGroups | select GroupName

# Lists groups managers => interesting if it is a user
Get-DomainManagedSecurityGroup

GroupName : Security Operations
GroupDistinguishedName : CN=Security
Operations,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
ManagerName : joe.evans
ManagerDistinguishedName : CN=Joe
Evans,OU=Security,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
ManagerType : User
ManagerCanWrite : UNKNOWN

# Then list the ACLs on this group to see what we could do if we compromised the manager
$sid = ConvertTo-SID <MANAGER>
Get-DomainObjectAcl -Identity '<MANAGER_GROUP>' | ?{$_.SecurityIdentifier -eq $sid}
```
