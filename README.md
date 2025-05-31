# Preventing Directory Traversal: Attacks A Developer’s Step-by-Step Security Guide

<img src="https://github.com/CracksoftShlok/DirectoryTraversalWebSec/blob/main/Image.png?raw=true" alt="Alt text" style="width: 100%; height: auto;" />

### Introduction: What is Directory Traversal?
Directory Traversal, also known as **Path Traversal**, is a critical security vulnerability in web applications. It allows attackers to access files and folders outside the intended directory—like sneaking into the staff-only server room of a hotel when you’re only allowed in the lobby.

This flaw can lead to serious problems such as data leaks, system compromise, and violation of privacy and compliance rules.

### Why This Matters

- Directory Traversal affects **41% of web apps** according to OWASP 2021.
- It can expose sensitive files such as passwords, configuration files, and system information.
- Major platforms like **Apache Tomcat**, **Magento**, and many **IoT devices** have been vulnerable to this bug.
- If exploited, it can lead to data breaches and even full server takeover.

### How Directory Traversal Works
#### The Basic Attack Example
A typical URL for viewing files might look like:
```
http://example.com/view.php?file=report.pdf
```
The backend PHP code might be:
```
include("documents/" . $_GET['file']);
```

This means the server will look for the file inside the `documents/` folder.
But an attacker can send:
```
http://example.com/view.php?file=../../../../etc/passwd
```

What happens? The `../` means “go up one folder.” Repeated `../` climb out of the `documents/` folder to the root directory, where `/etc/passwd` (the Linux user database) is stored. If successful, the attacker sees contents they should never access.

#### Operating System Differences

| OS      | Example Payload         | Sensitive Files                     |
| ------- | ----------------------- | ----------------------------------- |
| Linux   | `../../../etc/passwd`   | `/etc/shadow`, `/proc/self/environ` |
| Windows | `..\..\windows\win.ini` | `C:\Windows\System32\config\SAM`    |

### Advanced Exploitation Techniques

Attackers don’t just use simple `../` strings; they use tricks to bypass filters:
- **URL Encoding:**
    - `%2e%2e%2f` decodes to `../`
    - Double encoding: `%252e%252e%252f` → `%2e%2e%2f` → `../`
- **Null Byte Injection:**
    - Example: `../../config.php%00.jpg` tricks the server into reading `config.php` by terminating the string early.
- **Unicode Tricks:**
    - Using full-width dots like `%uff0e%uff0e/` which can be interpreted as `../`.
These tricks help attackers bypass simple filters that just block `../`.

### Real-World Examples of Directory Traversal

- **Apache Tomcat (CVE-2020-1938):**
    The AJP protocol allowed attackers to read any file on the server, affecting thousands of servers worldwide.
- **Magento (2019):**
    Attackers used traversal to steal database credentials by accessing `/../../app/etc/local.xml`.
- **GoAhead Web Server (IoT cameras):**
    A traversal bug allowed reading `/etc/passwd`, leading to 500,000 devices being compromised.

### Finding Directory Traversal Vulnerabilities

#### Manual Testing

Try inserting these payloads in URL/file parameters:
- `?file=....//....//etc/passwd`
- `?download=..%2f..%2fwin.ini`
- `?template=../../../../proc/self/cmdline`

If the app returns contents of these sensitive files, it’s vulnerable.

#### Automated Tools

| Tool       | Purpose                                |
| ---------- | -------------------------------------- |
| Burp Suite | Intercept and modify HTTP requests     |
| OWASP ZAP  | Automated scanning for vulnerabilities |
| FFUF       | Fast web fuzzing to discover paths     |
**Pro Tip:** Combine with Local File Inclusion (LFI) tests, such as:
```
?page=php://filter/convert.base64-encode/resource=index.php
```

### Prevention and Mitigation

#### Secure Coding Practices
- **Whitelist Allowed Files**
```
//PHP Code (SecurityShlok)
$allowed = ['report.pdf', 'invoice.doc'];
if (!in_array($_GET['file'], $allowed)) {
    die("Invalid file");
}
```
- **Path Canonicalization**
```
//Java Code (SecurityShlok)
File file = new File(BASE_DIR, userInput);
if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
    throw new SecurityException("Invalid path");
}
```

#### Server Configuration
- Run web servers with the **least privilege**.
- Disable directory listing in Apache or Nginx.
- Use **chroot jails** to isolate application file access.

#### Web Application Firewall (WAF)

Example WAF rule to block traversal attempts:
```
SecRule ARGS "@contains ../" "id:1001,deny,msg:'Path Traversal Attempt'"
```

### Linked Vulnerabilities

Directory Traversal often leads to or is linked with:
- **Local File Inclusion (LFI):** Including unwanted files in server-side code.
- **Remote Code Execution (RCE):** Running malicious code uploaded via traversal.
- **Sensitive Data Exposure:** Leaking configuration or credential files.

### Case Study: GoAhead Web Server
In 2022, a traversal bug in the GoAhead Web Server used by IP cameras allowed:
```
GET /../../etc/passwd
```
Attackers used this to compromise over 500,000 devices worldwide.

### Testing Checklist for Developers and Testers

- Test all file parameters with `../` payloads.
- Try encoded variants like `%2e%2e%2f`.
- Check for null byte `%00` bypasses.
- Look for unusual server responses or error messages.
- Test paths relevant to both Linux and Windows servers.

#### Best Part;

**Free Learning Resources:**  
If you want to learn more about Directory Traversal vulnerabilities, free resources like PortSwigger Academy, the OWASP Testing Guide, and HackTheBox challenges provide excellent tutorials and practical exercises.


**Why Directory Traversal is Still a Problem:**  
Directory Traversal remains a major security issue because many developers still trust user input too much, while attackers constantly find new ways to bypass filters, leading to potentially severe consequences.


**Action Steps to Protect Your Application:**  
To defend against Directory Traversal, regularly audit your file-handling code, use strict whitelist validation, monitor logs for suspicious activity, and perform consistent manual and automated security testing.
