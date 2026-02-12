# Security Controls

```shellscript
# Check Windows Defender status => RealTimeProtectionEnabled set to True = enabled
Get-MpComputerStatus

# Get app whitelist / blacklist
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Check if ConstrainedLanguage is enabled => locks down many powershell features
$ExecutionContext.SessionState.LanguageMode

# Show groups specifically delegated to read LAPS passwords
https://github.com/leoloobeek/LAPSToolkit
Find-LAPSDelegatedGroups

# Check for users that can read LAPS passwords that are less protected than delegated groups
https://github.com/leoloobeek/LAPSToolkit
Find-AdmPwdExtendedRights

# Search for computers that have LAPS enabled when passwords expire, and even the 
# randomized passwords in cleartext if our user has access
https://github.com/leoloobeek/LAPSToolkit
Get-LAPSComputers

# Check for firewall 
netsh advfirewall show allprofiles

# Check for Windows Defender
sc.exe query windefend
```
