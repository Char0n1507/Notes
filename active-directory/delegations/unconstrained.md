# Unconstrained

If an account (user or computer), with unconstrained delegations privileges, is compromised, an attacker must wait for a privileged user to authenticate on it (or [force it](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/)) using Kerberos. The attacker service will receive an ST (service ticket) containing the user's TGT. That TGT will be used by the service as a proof of identity to obtain access to a target service as the target user. Alternatively, the TGT can be used with [S4U2self abuse](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse) in order to gain local admin privileges over the TGT's owner.

### Enumeration

```shellscript
# Powerview
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
Get-DomainComputer -Unconstrained | Select Name, UserAccountControl

# Native AD module 
Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties TrustedForDelegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description
```
