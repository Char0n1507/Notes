# AZOwns

{% embed url="https://github.com/hausec/PowerZure" %}

{% embed url="https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows?pivots=windows-psgallery&tabs=powershell&view=azps-15.3.0" %}

Connecting to Azure from an admin PowerShell console

```ps1
$username = "<USER>"
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential $username, $password
Connect-AzAccount -Credential $Creds
```

### On a group

Adding a user to a group

```shellscript
Import-Module .\PowerZure.psd1
Add-AzureADGroupMember -Group "<GROUP>" -Username <USER>
Get-AzureADGroupMember -Group "<GROUP>"    # Check that our user was added 
```

### On a VM

Execute command in Azure VM

```shellscript
# PowerZure
Invoke-AzureRunCommand -VMName "<VM>" -Command <COMMAND>    

# Az PowerShell module
Invoke-AzVMRunCommand -ResourceGroupName "<GROUP_NAME>" -CommandId "RunPowerShellScript" -VMName "<VM>" -ScriptString "<COMMAND>"
```
