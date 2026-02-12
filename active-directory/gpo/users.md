# Users

### List users

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Will only list enabled users. Using bloodhound will reveal even disabled ones
nxc smb <IP> -u <USER> -p <PASSWORD> --users
nxc smb <IP> -u <USER> -p <PASSWORD> --rid-brute
nxc mssql <IP> -u <USER> -p <PASSWORD> --rid-brute

# Gathering Users with LDAP Anonymous
# First get the base domain (for the -b option)
ldapsearch -H ldap://monitored.htb -x -s base namingcontexts
ldapsearch -H ldap://<IP> -x -b "DC=<DC>,DC=<DC>" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
./windapsearch.py --dc-ip <IP> -u "" -U

# Brute force users
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <WORDLIST>

# Logged on users
nxc smb <IP> -u <USER> -p <PASSWORD> --loggedon-users

# Users description
nxc ldap <IP> -u <USER> -p <PASSWORD> -M get-desc-users
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
net user /domain 
```
{% endtab %}
{% endtabs %}

### User information

```shellscript
# PowerView
# Information on a specific user
Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Informations on all domain users exported to a CSV file for offline processing
Get-DomainUser * -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol | Export-Csv .\<NAME>.csv -NoTypeInformation

wmic useraccount list /format:list
wmic sysaccount list /format:list

net user <ACCOUNT_NAME> /domain
```

### User groups membership

```shellscript
# Will show nested group membership
Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name

# Will not show nested group membership
Get-ADUser -Identity <USER> -Properties * | select memberof | ft -Wrap
```
