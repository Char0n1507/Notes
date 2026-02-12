# PowerShell Filters

Filters in PowerShell allow you to process piped output more efficiently and retrieve exactly\
the information you need from a command. Filters can be used to narrow down specific data\
in a large result or retrieve data that can then be piped to another command.\
We can use filters with the `Filter` parameter.

The following operators can be used with the `Filter` parameter

<table data-header-hidden><thead><tr><th valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Logical Operator</strong></td><td valign="top"><strong>Description</strong></td><td valign="top"><strong>Equivalent LDAP operator/expression</strong></td></tr><tr><td valign="top">-eq</td><td valign="top">Equal to. This will <strong>not</strong> support wild card search.</td><td valign="top">=</td></tr><tr><td valign="top">-ne</td><td valign="top">Not equal to. This will <strong>not</strong> support wild card search.</td><td valign="top">! x = y</td></tr><tr><td valign="top">-like</td><td valign="top">Similar to -eq and supports wildcard comparison. The only wildcard character supported is: <strong>*</strong></td><td valign="top">=</td></tr><tr><td valign="top">-notlike</td><td valign="top">Not like. Supports wild card comparison.</td><td valign="top">! x = y</td></tr><tr><td valign="top">-approx</td><td valign="top">Approximately equal to</td><td valign="top">~=</td></tr><tr><td valign="top">-le</td><td valign="top">Lexicographically less than or equal to</td><td valign="top">&#x3C;=</td></tr><tr><td valign="top">-lt</td><td valign="top">Lexicographically less than</td><td valign="top">! x >= y</td></tr><tr><td valign="top">-ge</td><td valign="top">Lexicographically greater than or equal to</td><td valign="top">>=</td></tr><tr><td valign="top">-gt</td><td valign="top">Lexicographically greater than</td><td valign="top">! x &#x3C;= y</td></tr><tr><td valign="top">-and</td><td valign="top">AND</td><td valign="top">&#x26;</td></tr><tr><td valign="top">-or</td><td valign="top">OR</td><td valign="top">|</td></tr><tr><td valign="top">-not</td><td valign="top">NOT</td><td valign="top">!</td></tr><tr><td valign="top">-bor</td><td valign="top">Bitwise OR</td><td valign="top">:1.2.840.113556.1.4.804:=</td></tr><tr><td valign="top">-band</td><td valign="top">Bitwise AND</td><td valign="top">:1.2.840.113556.1.4.803:=</td></tr><tr><td valign="top">-recursivematch</td><td valign="top">Uses LDAP_MATCHING_RULE_IN_CHAIN (Win2k3 SP2 and above)</td><td valign="top">:1.2.840.113556.1.4.1941:=</td></tr></tbody></table>

The filter can be used with operators to compare, exclude, search for, etc., a variety of AD\
object properties. Filters can be wrapped in curly braces, single quotes, parentheses, or\
double-quotes. For example, the following simple search filter using `Get-ADUser` to find\
information about the user Sally Jones can be written as follows

```powershell
Get-ADUser -Filter "name -eq 'sally jones'"
Get-ADUser -Filter {name -eq 'sally jones'}
Get-ADUser -Filter 'name -eq "sally jones"'

# Find hosts with SLQ in their name, revealing interesting SQL servers 
Get-ADComputer -Filter "DNSHostName -like 'SQL*'"

# Find administrative groups
Get-ADGroup -Filter "adminCount -eq 1" | select Name

# It is possible to combine filters => find AS-REP Roastable admin users
Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}

# Find admin users with SPN not empty
Get-ADUser -Filter "adminCount -eq '1'" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl
```
