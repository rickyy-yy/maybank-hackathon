# Security Code Review Report

## Target Information
- **Domain**: teams.example.com
- **Review Date**: 2024-11-10
- **Reviewer**: Security Team
- **Repository**: https://github.com/example/teams-collaboration
- **Commit Hash**: 9b7e3f2a1c8d5f4b6e9a2d7c3f1e8b5a4d6c9f2e

---

## Executive Summary

This report identifies multiple Insecure Direct Object Reference (IDOR) vulnerabilities in the teams.example.com collaboration platform. These vulnerabilities allow unauthorized access to private team documents, messages, and user data through predictable resource identifiers.

---

## Vulnerability Details

### 1. IDOR in Document Download Endpoint

**Severity**: HIGH
**CWE**: CWE-authorization (Broken Access Control)
**CVSS Score**: 7.5
**File**: `src/api/documents/DocumentController.java:156`
**Git Commit**: 9b7e3f2a1c8d5f4b6e9a2d7c3f1e8b5a4d6c9f2e

#### Description
The document download endpoint accepts a document ID parameter but fails to verify that the requesting user has permission to access the document. Any authenticated user can download any document by guessing or enumerating document IDs.

#### Vulnerable Code
```java
@GetMapping("/api/documents/{documentId}/download")
public ResponseEntity<Resource> downloadDocument(
    @PathVariable Long documentId,
    @AuthenticationPrincipal UserDetails userDetails
) {
    // VULNERABLE: No authorization check
    Document document = documentRepository.findById(documentId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));

    Resource resource = new FileSystemResource(document.getFilePath());

    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + document.getFileName() + "\"")
        .body(resource);
}
```

#### Proof of Concept
```bash
# User A (ID: 123) creates a private document (ID: 5001)
# User B (ID: 456) can access it without authorization

# Authenticate as User B
TOKEN=$(curl -X POST https://teams.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"userB","password":"password"}' \
  | jq -r '.token')

# Download User A's private document
curl -X GET https://teams.example.com/api/documents/5001/download \
  -H "Authorization: Bearer $TOKEN" \
  -o stolen_document.pdf

# Enumerate all documents
for i in {5000..5100}; do
  curl -X GET "https://teams.example.com/api/documents/$i/download" \
    -H "Authorization: Bearer $TOKEN" \
    -o "doc_$i.pdf" 2>/dev/null
done
```

#### Impact
- Unauthorized access to confidential documents
- Data breach of proprietary information
- Privacy violations
- Compliance violations (GDPR, HIPAA, etc.)

#### Remediation
Implement proper authorization checks:

```java
@GetMapping("/api/documents/{documentId}/download")
public ResponseEntity<Resource> downloadDocument(
    @PathVariable Long documentId,
    @AuthenticationPrincipal UserDetails userDetails
) {
    Document document = documentRepository.findById(documentId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));

    // SECURE: Verify user has access to this document
    User currentUser = userRepository.findByUsername(userDetails.getUsername())
        .orElseThrow(() -> new UnauthorizedException("User not found"));

    if (!hasDocumentAccess(document, currentUser)) {
        throw new UnauthorizedException("Access denied");
    }

    Resource resource = new FileSystemResource(document.getFilePath());

    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + document.getFileName() + "\"")
        .body(resource);
}

private boolean hasDocumentAccess(Document document, User user) {
    // Check if user owns the document
    if (document.getOwnerId().equals(user.getId())) {
        return true;
    }

    // Check if user is in a team with access
    return document.getTeams().stream()
        .anyMatch(team -> team.getMembers().contains(user));
}
```

---

## Additional Findings

### 2. IDOR in Team Messages API

**Severity**: HIGH
**CWE**: CWE-639 (Authorization Bypass)
**File**: `src/api/messages/MessageController.java:89`

```java
@GetMapping("/api/messages/{messageId}")
public ResponseEntity<Message> getMessage(@PathVariable Long messageId) {
    // VULNERABLE: No team membership check
    Message message = messageRepository.findById(messageId)
        .orElseThrow(() -> new ResourceNotFoundException("Message not found"));

    return ResponseEntity.ok(message);
}
```

**Impact**: Users can read messages from teams they don't belong to.

**Remediation**:
```java
@GetMapping("/api/messages/{messageId}")
public ResponseEntity<Message> getMessage(
    @PathVariable Long messageId,
    @AuthenticationPrincipal UserDetails userDetails
) {
    Message message = messageRepository.findById(messageId)
        .orElseThrow(() -> new ResourceNotFoundException("Message not found"));

    User currentUser = userRepository.findByUsername(userDetails.getUsername())
        .orElseThrow(() -> new UnauthorizedException("User not found"));

    // Verify user is member of the team
    if (!message.getTeam().getMembers().contains(currentUser)) {
        throw new UnauthorizedException("Access denied");
    }

    return ResponseEntity.ok(message);
}
```

### 3. IDOR in User Profile Updates

**Severity**: MEDIUM
**File**: `src/api/users/UserController.java:203`

```java
@PutMapping("/api/users/{userId}")
public ResponseEntity<User> updateUser(
    @PathVariable Long userId,
    @RequestBody UserUpdateRequest request
) {
    // VULNERABLE: Any user can update any profile
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));

    user.setEmail(request.getEmail());
    user.setPhoneNumber(request.getPhoneNumber());
    userRepository.save(user);

    return ResponseEntity.ok(user);
}
```

**Impact**: Account takeover through email modification.

**Remediation**:
```java
@PutMapping("/api/users/{userId}")
public ResponseEntity<User> updateUser(
    @PathVariable Long userId,
    @RequestBody UserUpdateRequest request,
    @AuthenticationPrincipal UserDetails userDetails
) {
    User currentUser = userRepository.findByUsername(userDetails.getUsername())
        .orElseThrow(() -> new UnauthorizedException("User not found"));

    // Users can only update their own profile (unless admin)
    if (!currentUser.getId().equals(userId) && !currentUser.isAdmin()) {
        throw new UnauthorizedException("Access denied");
    }

    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));

    user.setEmail(request.getEmail());
    user.setPhoneNumber(request.getPhoneNumber());
    userRepository.save(user);

    return ResponseEntity.ok(user);
}
```

---

## Recommendations

1. **Immediate Actions**:
   - Deploy authorization fixes for all identified endpoints
   - Audit access logs for unauthorized document/message access
   - Implement rate limiting to prevent enumeration attacks
   - Notify affected users if data was accessed

2. **Long-term Improvements**:
   - Implement centralized authorization service/middleware
   - Use UUIDs instead of sequential integers for resource IDs
   - Add automated authorization testing
   - Implement attribute-based access control (ABAC)
   - Regular penetration testing
   - Security training on access control patterns
   - Code review checklist for authorization

3. **Detection and Monitoring**:
   - Log all resource access attempts
   - Alert on unusual access patterns (rapid ID enumeration)
   - Implement anomaly detection

---

## Testing Recommendations

Create automated tests for authorization:
```java
@Test
public void testUserCannotAccessOtherUsersDocuments() {
    User userA = createTestUser("userA");
    User userB = createTestUser("userB");
    Document privateDoc = createDocument(userA, "private.pdf");

    // Authenticate as userB
    String token = authenticateUser(userB);

    // Attempt to access userA's document
    ResponseEntity<Resource> response = restTemplate.exchange(
        "/api/documents/" + privateDoc.getId() + "/download",
        HttpMethod.GET,
        new HttpEntity<>(createHeaders(token)),
        Resource.class
    );

    // Should return 403 Forbidden
    assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
}
```

---

## Timeline
- **Discovery**: 2024-11-07
- **Verification**: 2024-11-08
- **Report Delivered**: 2024-11-10
- **Expected Fix**: 2024-11-13

---

## References
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP Access Control Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
