# 3306 - MySQL

### Service enumeration

#### Scan

```sh
sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

#### Service interaction

```sh
mysql -u <USER> -p<PASS> -h <IP>
```

#### Syntax

```shellscript
# View privileges of our user
SHOW GRANTS; 

# List the structure of a table
DESCRIBE <table_name>;
```
