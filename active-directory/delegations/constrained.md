# Constrained

If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user (e.g. domain admin, except users protected against delegation) in the environment to access another service the initial one can delegate to.

### Enumeration

```shellscript
# Powerview
Get-DomainUser -TrustedToAuth | Select SamAccountName, msDS-AllowedToDelegateTo, UserAccountControl
Get-DomainComputer -TrustedToAuth | Select DnsHostName, msDS-AllowedToDelegateTo

# Native AD module => Get-ADObject will list users and computers at once
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
Get-ADUser svc_web -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation
```
