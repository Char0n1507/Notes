# Detection Evasion

### PowerShell downgrade

```ps1
# Get informations on current powershell
Get-Host

# Downgrade powershell
powershell.exe -version 2

# Check if downgraded
Get-Host
```

### Bypassing PowerShell Securities

PowerShell detections :

* System-wide transcription
* Script Block logging
* AntiMalware Scan Interface (AMSI)
* Constrained Language Mode (CLM)

{% embed url="https://github.com/OmerYa/Invisi-Shell" %}

{% embed url="https://medium.com/@legionoffensivesec/invisi-shell-making-your-powershell-invisible-08bd8123fda7" %}

The Invisi-Shell project is able to bypass all detections mentioned above

```shellscript
# Without admin privileges
.\RunWithRegistryNonAdmin.bat

# With admin privileges
.\RunWithPathAsAdmin.bat

# Type exit from the new PowerShell session to complete the clean-up when done
```

### Bypassing AV Signatures for PowerShell

If we can bypass AMSI, any script that gets loaded in memory would be fine to execute

But if we want to bypass signature based detection of on-disk PowerShell scripts by Windows Defender, we can use AMSITrigger.

AMSITrigger will voluntarily trigger AMSI, so that it sends the code to the AV, and it will output which parts of it are being flagged as malicious.

{% hint style="info" %}
Steps to avoid signature based detection:

1. Scan using AMSITrigger
2. Modify the detected code snippet
3. Re-scan using AMSITrigger
4. Repeat the steps 2 & 3 till we get a result as “AMSI\_RESULT\_NOT\_DETECTED” or “Blank”
{% endhint %}

{% embed url="https://www.rythmstick.net/posts/amsitrigger/" %}

{% embed url="https://github.com/RythmStick/AMSITrigger" %}

```shellscript
# Shows triggers as well as line numbers
.\AmsiTrigger.exe -i=<PATH_TO_SCRIPT> -f=2

# Example 
PS C:\Tools> .\AmsiTrigger.exe -i="Inveigh.ps1" -f=2
[6621]  "[System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        $JSONArray | ForEach-Object -Process {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $JSONArray.count * 100)
```

Once we know which part is problematic, we can obfuscate it. AMSITrigger won't output the exact line which triggered the detection, but the code block, so we need to trial and error.

To help us with obfuscation, we can use Invoke-Obfuscation.

{% embed url="https://github.com/danielbohannon/Invoke-Obfuscation" %}

{% embed url="https://iritt.medium.com/an-easy-guide-to-obfuscating-powershell-scripts-with-invoke-obfuscation-6fa3c8626ed3" %}

```shellscript
# Get to the root user
sudo su

# Switch to powershell 
pwsh

# Check the execution policy (should be unrestricted)
Get-ExecutionPolicy

# Import the module 
Import-Module ./Invoke-Obfuscation.psd1

# Run the tool
Invoke-Obfuscation

# Load a script block
SET SCRIPTBLOCK <script>

# Choose between the given options
[*] TOKEN       Obfuscate PowerShell command Tokens
[*] AST         Obfuscate PowerShell Ast nodes (PS3.0+)
[*] STRING      Obfuscate entire command as a String
[*] ENCODING    Obfuscate entire command via Encoding
[*] COMPRESS    Convert entire command to one-liner and Compress
[*] LAUNCHER    Obfuscate command args w/Launcher techniques (run once at end)

# Then choose the option to apply
Invoke-Obfuscation> STRING

[*] STRING\1    Concatenate entire command
[*] STRING\2    Reorder entire command after concatenating
[*] STRING\3    Reverse entire command after concatenating

# Get the obfuscated code
Invoke-Obfuscation\String> 1

Executed:
  CLI:  String\1
  FULL: Out-ObfuscatedStringCommand -ScriptBlock $ScriptBlock 1                                                                                                                                                                             
                                                                                                                                                                                                                                            
Result:
('[S'+'yst'+'em.Dia'+'gnos'+'t'+'ics'+'.Stopwat'+'ch]:'+':Sta'+'rtNew()') | & ((GV '*MDR*').NAme[3,11,2]-jOIN'')
```

Finally, replace the original part of the code with the obfuscated one and repeat the process for each trigger. When the different parts have been obfuscated, scan again with AMSITrigger until the script does not trigger anything

```shellscript
PS C:\Tools> .\AmsiTrigger.exe -i="Inveigh.ps1" -f=2
[+] AMSI_RESULT_NOT_DETECTED
```

We can then use the obfuscated script on a windows machine with AV enabled

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FhLwL4aDLgV3ooHJknDtB%2Fimage.png?alt=media&#x26;token=ff7293ad-4ad8-491b-b6d6-db49d9f00004" alt=""><figcaption></figcaption></figure>
