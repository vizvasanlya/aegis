# Red Team Infrastructure

What you need to set up and how much it costs.

---

## The Three Pillars

### 1. C2 Server (Command and Control)

A server that deployed agents connect back to for instructions.

**Software options:**

| Tool | Cost | Difficulty | Best For |
|------|------|-----------|----------|
| Sliver | Free | Easy | Solo operators, small teams |
| Havoc | Free | Medium | Teams wanting modern UI |
| Mythic | Free | Medium | Complex engagements |
| Cobalt Strike | $5,900/yr | Easy | Enterprise red teams |

**Hosting:**

| Provider | Monthly Cost | Specs |
|----------|-------------|-------|
| Hetzner | $4-5 | 2 vCPU, 4GB RAM |
| DigitalOcean | $6 | 1 vCPU, 1GB RAM |
| Vultr | $5 | 1 vCPU, 1GB RAM |
| AWS Lightsail | $5 | 1 vCPU, 1GB RAM |

**Setup time:** 1-2 hours for Sliver, 4-8 hours for Mythic.

### 2. Phishing Infrastructure

Lookalike domains and email sending for social engineering.

**Components:**

| Component | Cost | Example |
|-----------|------|---------|
| Lookalike domain | $10-15/year | techcorp-security.com |
| SSL certificate | Free | Let's Encrypt |
| Email service | Free tier | SendGrid (100 emails/day) |
| Landing page hosting | Free | GitHub Pages, Cloudflare Pages |

**Total:** $10-15/year for the domain, everything else free.

### 3. Redirectors and Pivots

Servers that hide your real infrastructure and enable network pivoting.

| Component | Cost | Purpose |
|-----------|------|---------|
| Redirector VPS | $5/month | Hide C2 server location |
| Chisel/Ligolo | Free | SOCKS proxy for internal pivoting |
| DNS server | Free | DNS tunneling for stealthy C2 |

---

## Complete Cost Breakdown

### Budget Setup (Solo Operator)

| Item | Monthly | Yearly |
|------|---------|--------|
| VPS for C2 (Hetzner) | $5 | $60 |
| Phishing domain | — | $12 |
| SSL certificate | $0 | $0 |
| Email service | $0 | $0 |
| C2 software (Sliver) | $0 | $0 |
| **Total** | **$5/month** | **$72/year** |

### Professional Setup (Small Team)

| Item | Monthly | Yearly |
|------|---------|--------|
| C2 server (dedicated) | $20 | $240 |
| Redirector VPS | $10 | $120 |
| Phishing infrastructure | — | $50 |
| Email service (paid tier) | $20 | $240 |
| Domain privacy | — | $10 |
| **Total** | **$50/month** | **$660/year** |

### Enterprise Setup (Red Team Firm)

| Item | Monthly | Yearly |
|------|---------|--------|
| Cobalt Strike license | — | $5,900 |
| Multiple C2 servers | $100 | $1,200 |
| Redirector network | $50 | $600 |
| Phishing platform | $200 | $2,400 |
| Email infrastructure | $100 | $1,200 |
| Physical tools | — | $2,000 |
| **Total** | **$450/month** | **$11,300/year** |

---

## Setup Guide

### Step 1: Get a VPS

```bash
# After purchasing from Hetzner/DigitalOcean/Vultr
ssh root@your-vps-ip

# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
```

### Step 2: Install C2 Framework (Sliver example)

```bash
# Install Sliver
docker run -d --name sliver -p 80:80 -p 443:443 -p 8888:8888 \
  ghcr.io/bishopfox/sliver-server:latest

# Generate server certificate
docker exec -it sliver sliver-server cert

# Access the console
docker exec -it sliver sliver-server
```

### Step 3: Get a Phishing Domain

```bash
# Buy from Namecheap, Cloudflare, or Google Domains
# Example: techcorp-security.com ($12/year)

# Point DNS to your VPS
# A record: techcorp-security.com → your-vps-ip
# MX record: techcorp-security.com → your-vps-ip (for email)

# Get SSL certificate
apt install certbot
certbot certonly --standalone -d techcorp-security.com
```

### Step 4: Set Up Email Sending

```bash
# Option A: SendGrid (free tier)
# Sign up at sendgrid.com, verify domain, get API key

# Option B: Mailgun (free tier)
# Sign up at mailgun.com, verify domain

# Option C: Self-hosted (advanced)
# Install mail-in-a-box or mailcow
```

### Step 5: Configure Aegis

```bash
# Set environment variables
export AEGIS_LLM="openai/gpt-4o"
export LLM_API_KEY="your-api-key"

# Configure C2 integration
export SLIVER_SERVER="your-vps-ip:8888"
export SLIVER_API_KEY="your-api-key"

# Configure phishing
export PHISH_DOMAIN="techcorp-security.com"
export SENDGRID_API_KEY="your-key"
```

---

## Security Considerations

**Protect your infrastructure:**
- Use strong passwords on all servers
- Enable fail2ban for SSH
- Use VPN to access C2 (don't expose console publicly)
- Keep all software updated
- Use encrypted communications (Signal, not Slack)

**Legal protection:**
- Never run red team ops without written authorization
- Keep the Rules of Engagement document accessible
- Log everything — your own activity is evidence too
- Have a lawyer review the engagement contract

**Operational security:**
- Use separate infrastructure for each engagement
- Don't reuse phishing domains across clients
- Clean up completely after each engagement
- Compartmentalize — each team member needs minimal access
