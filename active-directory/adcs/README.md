# ADCS

## ADCS

Certipy wiki :

{% embed url="https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation" %}

### Certificate mapping

Certificate mapping is the part of certificate authentication where the DC takes the principal (user or computer) data provided in the certificate used during authentication, and attempts to map it to a user or computer in the domain.

### StrongCertificateBindingEnforcement

* If the registry key value is `0` and the certificate contains an UPN value (normally for a user account), the KDC will first try to associate the certificate with a user whose `userPrincipalName` attribute matches. If no validation can be performed, the KDC looks for an account whose `sAMAccountName` property matches. If it doesn't find one, it tries again by adding a `$` to the end of the user name. That way, a certificate with a UPN can be associated with a machine account.
* If the registry key value is `1` or `2`, and no explicit mapping is in place, the `szOID_NTDS_CA_SECURITY_EXT` security extension will be used to implicitly map the account using its `objectSid`. If the registry key is set to `1` and no security extension is present, the mapping behaviour is similar to that of a registry key set to `0`.
