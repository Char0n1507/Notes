# AZContributor

{% embed url="https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows?pivots=windows-psgallery&tabs=powershell&view=azps-15.3.0" %}

Connecting to Azure from an admin PowerShell console

```powershell
$username = "<USER>"
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential $username, $password
Connect-AzAccount -Credential $Creds
```

### On an Azure Key Vault

```shellscript
# Get the name of the secret within the vault (Name property)
Get-AzKeyVaultSecret -VaultName <VAULT>

# Convert the secure string password back to plain text
Get-AzKeyVaultSecret -VaultName <VAULT> -Name <SECRET_NAME>
[System.Net.NetworkCredential]::new('', $secret.SecretValue).Password
```
