# 873 - Rsync

Rsync is a fast and efficient tool for locally and remotely copying files. It can be used to copy files locally on a given machine and to/from remote hosts

### Service enumeration

#### Scan

```sh
sudo nmap -sV -p 873 <IP>
nmap -sV --script "rsync-list-modules" -p 873 <IP>
```

#### List available shares

```sh
nc -nv <IP> 873
# list
```

#### Enumerate a share

```sh
rsync -av --list-only rsync://<IP>/<SHARE>

# If creds are needed
rsync -av --list-only rsync://<USER>@<IP>/<SHARE>
```

#### Copy files from a share

```sh
rsync -av rsync://<IP>:<PORT>/<SHARE> ./rsyn_shared

# If creds are needed
rsync -av rsync://<USER>@<IP>:<PORT>/<SHARE ./rsyn_shared
```

{% embed url="https://book.hacktricks.wiki/en/network-services-pentesting/873-pentesting-rsync.html" %}

{% embed url="https://phoenixnap.com/kb/how-to-rsync-over-ssh" %}
