# HTTP Verb Tampering

## HTTP Verb Tampering

An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods. This can be exploited by sending malicious requests using unexpected methods, which may lead to bypassing the web application's authorization mechanism or even bypassing its security controls against other web attacks

| Verb      | Description                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------- |
| `HEAD`    | Identical to a GET request, but its response only contains the `headers`, without the response body |
| `PUT`     | Writes the request payload to the specified location                                                |
| `DELETE`  | Deletes the resource at the specified location                                                      |
| `OPTIONS` | Shows different options accepted by a web server, like accepted HTTP verbs                          |
| `PATCH`   | Apply partial modifications to the resource at the specified location                               |

### Bypassing Basic Authentication

```shellscript
# See what request types the server allows
curl -i -X OPTIONS <URL>
```

If a GET request needs auth, change the request method to POST and forward it to see if the action gets executed. Use burp's `Change request method` to change a GET into POST or vice versa

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FzX9a1Rh1384xaJikicrg%2Fimage.png?alt=media&#x26;token=2395608b-91d3-442b-8cf1-81b11093a791" alt=""><figcaption></figcaption></figure>

Try other methods ⇒ if the server if poorly configured, the action requesting authentication could be executed regardless

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FeuYkZ0ur3VfjxDFfnzX4%2Fimage.png?alt=media&#x26;token=04c377c1-6c4a-469d-bca4-5a7c7b794ff8" alt=""><figcaption></figcaption></figure>

### Bypassing Security Filters

This is commonly found in security filters that detect malicious requests. For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in POST parameters (e.g. `$_POST['parameter']`), it may be possible to bypass it by simply changing the request method to GET.

In the File Manager web application, if we try to create a new file name with special characters in its name (e.g. test;), we get the following message

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F4Y92e0t3fBT7edBRucwn%2Fimage.png?alt=media&#x26;token=e00a6e29-be79-4d15-bc82-4b253da9e886" alt=""><figcaption></figcaption></figure>

Use “Change request method”, and the file is created ⇒ it is normal if when we switch from GET to POST the injection is not in the URL requested

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FIrYae65S7BulmdnR74eP%2Fimage.png?alt=media&#x26;token=7bb6e3d2-1b9a-435a-9c33-794e7c362ea5" alt=""><figcaption></figcaption></figure>
