import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.database import async_session_maker
from app.models.template import RemediationTemplate


async def load_templates():
    """Load remediation templates into database"""

    templates = [
        {
            "vulnerability_type": "SQL Injection",
            "cwe_id": "CWE-89",
            "title": "SQL Injection Remediation",
            "description": "SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands.",
            "remediation_steps": """1. Use parameterized queries (prepared statements) for all database interactions
2. Implement input validation using allowlists for expected values
3. Use stored procedures with parameterized inputs
4. Apply principle of least privilege to database accounts
5. Implement proper error handling to avoid information disclosure
6. Use ORM frameworks that automatically handle parameterization
7. Enable SQL query logging and monitoring for suspicious patterns""",
            "code_examples": """# VULNERABLE CODE (Python)
query = f"SELECT * FROM users WHERE username = '{user_input}'"
cursor.execute(query)

# SECURE CODE (Python with parameterized query)
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (user_input,))

# SECURE CODE (Python with ORM)
from sqlalchemy import text
query = text("SELECT * FROM users WHERE username = :username")
result = session.execute(query, {"username": user_input})""",
            "effort_hours": 8,
            "required_skills": ["backend_development", "database", "security"],
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        },
        {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "cwe_id": "CWE-79",
            "title": "XSS Vulnerability Remediation",
            "description": "XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
            "remediation_steps": """1. Encode all user-supplied data before rendering in HTML
2. Use Content Security Policy (CSP) headers
3. Implement context-aware output encoding
4. Validate and sanitize input on server-side
5. Use modern frameworks that auto-escape by default (React, Angular, Vue)
6. Avoid innerHTML and use textContent or safer alternatives
7. Sanitize HTML if user-generated HTML is absolutely necessary using DOMPurify""",
            "code_examples": """// VULNERABLE CODE (JavaScript)
element.innerHTML = userInput;

// SECURE CODE (JavaScript)
element.textContent = userInput;

// SECURE CODE (React - automatic escaping)
return <div>{userInput}</div>;

// SECURE CODE (with DOMPurify for HTML)
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// CSP Header
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'""",
            "effort_hours": 6,
            "required_skills": ["frontend_development", "security"],
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        },
        {
            "vulnerability_type": "SSL/TLS Vulnerabilities",
            "cwe_id": "CWE-327",
            "title": "SSL/TLS Security Hardening",
            "description": "Weak SSL/TLS configurations allow man-in-the-middle attacks and data interception.",
            "remediation_steps": """1. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
2. Enable TLS 1.2 and TLS 1.3 only
3. Use strong cipher suites (ECDHE, AES-GCM)
4. Disable weak ciphers (RC4, DES, 3DES, MD5)
5. Implement HSTS (HTTP Strict Transport Security)
6. Use valid, trusted SSL certificates
7. Enable certificate transparency
8. Configure perfect forward secrecy""",
            "code_examples": """# Nginx Configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Apache Configuration
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on

# Test with: openssl s_client -connect your-server.com:443 -tls1_2""",
            "effort_hours": 4,
            "required_skills": ["system_administration", "networking", "security"],
            "references": [
                "https://wiki.mozilla.org/Security/Server_Side_TLS",
                "https://cipherlist.eu/"
            ]
        },
        {
            "vulnerability_type": "Authentication Bypass",
            "cwe_id": "CWE-287",
            "title": "Authentication Security Hardening",
            "description": "Weak authentication mechanisms allow unauthorized access to protected resources.",
            "remediation_steps": """1. Implement multi-factor authentication (MFA)
2. Use strong password policies (min 12 characters, complexity requirements)
3. Implement account lockout after failed attempts
4. Use secure session management (HTTPOnly, Secure flags)
5. Implement proper password hashing (bcrypt, Argon2, scrypt)
6. Never store passwords in plain text
7. Implement rate limiting on authentication endpoints
8. Use CAPTCHA for login forms
9. Monitor and alert on suspicious authentication patterns""",
            "code_examples": """# VULNERABLE CODE (Python)
if user.password == input_password:
    login_user(user)

# SECURE CODE (Python with bcrypt)
import bcrypt

# During registration
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
user.password_hash = hashed

# During login
if bcrypt.checkpw(input_password.encode('utf-8'), user.password_hash):
    login_user(user)

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'""",
            "effort_hours": 12,
            "required_skills": ["backend_development", "security", "authentication"],
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ]
        },
        {
            "vulnerability_type": "Default Credentials",
            "cwe_id": "CWE-798",
            "title": "Default Credentials Removal",
            "description": "Systems using default or hardcoded credentials are easily compromised.",
            "remediation_steps": """1. Change all default passwords immediately
2. Remove or disable default accounts
3. Implement forced password change on first login
4. Use environment variables for credentials
5. Implement secure credential management (HashiCorp Vault, AWS Secrets Manager)
6. Conduct regular audits for default credentials
7. Use unique credentials per environment
8. Implement password rotation policies""",
            "code_examples": """# VULNERABLE CODE (hardcoded credentials)
database_url = "postgresql://admin:admin123@localhost/mydb"

# SECURE CODE (environment variables)
import os
database_url = os.environ.get('DATABASE_URL')

# SECURE CODE (with secrets management)
import boto3
import json

def get_secret():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId='prod/database')
    return json.loads(response['SecretString'])

credentials = get_secret()
database_url = credentials['connection_string']""",
            "effort_hours": 2,
            "required_skills": ["system_administration", "devops"],
            "references": [
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
            ]
        },
        {
            "vulnerability_type": "Security Misconfiguration",
            "cwe_id": "CWE-16",
            "title": "Security Configuration Hardening",
            "description": "Insecure default configurations expose systems to attacks.",
            "remediation_steps": """1. Remove default accounts, passwords, and sample files
2. Disable unnecessary services, features, and ports
3. Implement security headers (X-Frame-Options, X-Content-Type-Options, CSP)
4. Keep all software and dependencies updated
5. Use security benchmarks (CIS, NIST)
6. Implement principle of least privilege
7. Enable security logging and monitoring
8. Regular security configuration audits""",
            "code_examples": """# Security Headers (Express.js)
const helmet = require('helmet');
app.use(helmet());

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

# Docker Security
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
USER nodejs

# Kubernetes Security Context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true""",
            "effort_hours": 8,
            "required_skills": ["devops", "security", "system_administration"],
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                "https://www.cisecurity.org/cis-benchmarks"
            ]
        }
    ]

    async with async_session_maker() as session:
        try:
            # Clear existing templates using text() for raw SQL
            await session.execute(text("DELETE FROM remediation_templates"))

            # Insert templates
            for template_data in templates:
                template = RemediationTemplate(**template_data)
                session.add(template)

            await session.commit()
            print(f"✅ Loaded {len(templates)} remediation templates successfully!")

        except Exception as e:
            print(f"❌ Error loading templates: {e}")
            await session.rollback()
            raise


if __name__ == "__main__":
    print("Loading remediation templates...")
    asyncio.run(load_templates())