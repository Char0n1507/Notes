# Splunk

### Discovery / Footprinting

The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are `admin:changeme`, which are conveniently displayed on the login page.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FfEeQIwekc50uINsKHsrN%2Fchangme.png?alt=media&#x26;token=d2d0fb25-01f8-4226-949a-42b2864cf067" alt=""><figcaption></figcaption></figure>

The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication. It is not uncommon for system administrators to install a trial of Splunk to test it out, which is subsequently forgotten about. This will automatically convert to the free version that does not have any form of authentication, introducing a security hole in the environment

We need to access splunk through HTTPS !

As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system. A quick way to gain RCE is by creating a scripted input that tells Splunk to run a Python reverse shell script

Splunk version ⇒ top right button help ⇒ `About`

### Attacking

{% embed url="https://github.com/0xjpuff/reverse_shell_splunk" %}

In the `bin` directory of the repo, we have scritps for reverse shell from splunk. In the `default` directory, we have our `inputs.conf` file => tells Splunk which script to run and any conditions => here we tell Splunk to run the script every 10s

```shellscript
# Modify the script with our IP and PORT ans compress the files
tar -cvzf updater.tar.gz splunk_shell/
```

Go to `Install app from file` ⇒ Upload page and upload
