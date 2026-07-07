# System Hardening

---

## What Is Hardening?

Reducing the attack surface by disabling unnecessary features, applying patches, and configuring systems securely. Think of it as locking all the doors and windows before an attacker tries to break in.

---

## Server Hardening Checklist

### Operating System

- [ ] Remove default accounts (guest, admin)
- [ ] Disable unnecessary services
- [ ] Apply all security patches
- [ ] Configure automatic updates
- [ ] Set strong password policy
- [ ] Enable audit logging
- [ ] Restrict sudo access
- [ ] Disable SSH root login
- [ ] Use key-based SSH authentication
- [ ] Set idle timeout for sessions

### Web Server

- [ ] Remove server version header
- [ ] Disable directory listing
- [ ] Enable HTTPS only
- [ ] Set secure TLS configuration (TLS 1.2+)
- [ ] Configure HSTS header
- [ ] Set Content-Security-Policy
- [ ] Enable X-Frame-Options
- [ ] Disable unnecessary HTTP methods
- [ ] Limit request body size

### Database

- [ ] Change default credentials
- [ ] Disable remote access (if not needed)
- [ ] Enable encryption at rest
- [ ] Enable encryption in transit
- [ ] Restrict network access
- [ ] Enable audit logging
- [ ] Regular backups (tested restores)

### Cloud (AWS/Azure/GCP)

- [ ] Enable MFA on all accounts
- [ ] Use IAM roles (not long-lived keys)
- [ ] Enable CloudTrail/audit logging
- [ ] Restrict security groups
- [ ] Enable encryption on all storage
- [ ] Enable GuardDuty/Cloud Security Posture Management
- [ ] Review IAM policies quarterly

---

## Application Hardening

### Authentication

- [ ] Enforce strong passwords (12+ characters)
- [ ] Implement MFA for all admin accounts
- [ ] Set session timeout (30 min idle)
- [ ] Lock accounts after 5 failed attempts
- [ ] Use secure password hashing (bcrypt, Argon2)

### Authorization

- [ ] Implement least privilege access
- [ ] Review access permissions quarterly
- [ ] Remove unused accounts
- [ ] Implement role-based access control (RBAC)
- [ ] Audit admin actions

### Input Validation

- [ ] Validate all user input server-side
- [ ] Use parameterized queries (prevent SQLi)
- [ ] Encode output (prevent XSS)
- [ ] Validate file uploads (type, size, content)
- [ ] Rate limit API endpoints

### Configuration

- [ ] Remove debug mode in production
- [ ] Disable verbose error messages
- [ ] Set secure cookies (HttpOnly, Secure, SameSite)
- [ ] Implement CSP headers
- [ ] Remove default credentials

---

## Quick Wins (High Impact, Low Effort)

| Action | Impact | Effort |
|--------|--------|--------|
| Enable MFA on all admin accounts | Blocks 99% of credential attacks | 1 hour |
| Patch all systems | Fixes known vulnerabilities | 1 day |
| Disable SSH root login | Prevents direct root access | 5 minutes |
| Enable automatic updates | Keeps systems patched | 30 minutes |
| Remove default credentials | Eliminates easy access | 1 hour |
