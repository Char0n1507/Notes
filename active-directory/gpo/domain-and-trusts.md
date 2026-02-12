# Domain and Trusts

Types of trust :

* `Parent-child`: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain `corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
* `Cross-link`: A trust between child domains to speed up authentication.
* `External`: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes [SID filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) or filters out authentication requests (by SID) not from the trusted domain.
* `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
* `Forest`: A transitive trust between two forest root domains.
* [ESAE](https://docs.microsoft.com/en-us/security/compass/esae-retirement): A bastion forest used to manage Active Directory.
* A `transitive` trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if `Domain A` has a trust with `Domain B`, and `Domain B` has a `transitive` trust with `Domain C`, then `Domain A` will automatically trust `Domain C`.
* In a `non-transitive trust`, the child domain itself is the only one trusted.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F712oyC30PLy3iaBpmram%2Fimage.png?alt=media&#x26;token=e47dbd8f-c551-46ba-815a-5b5f284db1e5" alt=""><figcaption></figcaption></figure>

### Domain information

{% tabs %}
{% tab title="PowerView" %}
```shellscript
# Domain information
Get-Domain
Get-Domain -Domain <DOMAIN>

# Domain SID
Get-DomainSID

# Domain policy
Get-DomainPolicyData
Get-DomainPolicyData -Domain <DOMAIN>

# Domain controller information
Get-DomainController
Get-DomainController -Domain <DOMAIN>
```
{% endtab %}

{% tab title="AD module" %}
```shellscript
# Domain information
Get-ADDomain
Get-ADDomain -Identity <DOMAIN>

# Domain SID
(Get-ADDomain).DomainSID

# Domain controller information
Get-ADDomainController
Get-ADDomainController -DomainName <DOMAIN> -Discover
```
{% endtab %}

{% tab title="Wmic" %}
```shellscript
# Domain information
wmic ntdomain list /format:list
```
{% endtab %}
{% endtabs %}

### Trust relationships

```shellscript
# Powershell
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# ActiveDirectory module
Get-ADTrust -Filter *

# PowerView
Get-DomainTrust 
Get-DomainTrustMapping

# Cmd
netdom query /domain:<CURRENT_DOMAIN> trust
```

### Enumerate users across trusts

```shellscript
# PowerView
Get-DomainUser -Domain <CHILD_DOMAIN> | select SamAccountName
```

### Enumerate computers across trusts

```shellscript
# PowerView
Get-DomainComputer -Domain <CHILD_DOMAIN> -Properties DNSHostName

# Cmd
netdom query /domain:<CURRENT_DOMAIN> workstation
```
