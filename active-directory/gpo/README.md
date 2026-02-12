# GPO

Group Policy provides systems administrators with a centralized way to manage configuration settings and manage operating systems and user and computer settings in a Windows environment. A Group Policy Object (GPO) is a collection of policy settings. GPOs include policies such as screen lock timeout, disabling USB ports, domain password policy, push out software, manage applications, and more. GPOs can be applied to individual users and hosts or groups by being applied directly to an Organizational Unit (OU). Gaining rights over a GPO can lead to lateral vertical movement up to full domain compromise and can also be used as a persistence mechanism.

```shellscript
# List GPO names of the domain
Get-DomainGPO | select displayname    # PowerView             
Get-GPO -All | Select DisplayName     # AD module

# List GPO applied to a specific computer                  
Get-DomainGPO -ComputerName <COMPUTER> | select displayname 

# We can also use a built-in tool that determines GPO that have been applied
gpresult /r /user:<USER>
gpresult /r /S <COMPUTER>

# After reviewing all of the GPOs applied throughout the domain, it is always good to look at
# GPO permissions. We can use the SID for the Domain Users group to see if this group has any 
# permissions assigned to any GPOs.
# Try it with groups our user is part of, not limited to Domain Users
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

# Baed on the previous result, convert the GPO GUID to the GPO Name 
# The GUID is the content of CN property in ObjectDN 
Get-GPO -Guid <GUID>

# With the GPO name, we can check in bloodhound that the Domain Users group has privs
# over the GPO. Then select the GPO and scroll down to Affected Objects on the Node info 
# tab. We can see to which objects the GPO is applied. We could then use the below tool
# to take advantage of the GPO misconfiguration by performing actions such as adding a 
# user that we control to the local admins group on one of the affected hosts, creating an
# immediate scheduled task on one of the hosts to give us a reverse shell, or configure a
# malicious computer startup script to provide us with a reverse shell or similar
https://github.com/FSecureLABS/SharpGPOAbuse
```
