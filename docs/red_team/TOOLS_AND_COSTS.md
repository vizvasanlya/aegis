# Red Team Tools and Costs

Complete inventory of tools used in red team operations with pricing.

---

## Category 1: Reconnaissance

| Tool | Purpose | Cost |
|------|---------|------|
| subfinder | Subdomain enumeration | Free |
| amass | Attack surface mapping | Free |
| nmap | Port scanning | Free |
| naabu | Fast port scanner | Free |
| httpx | HTTP probing | Free |
| katana | Web crawling | Free |
| Shodan | Internet-wide scanning | Free (limited) / $59/mo |
| Censys | Certificate transparency | Free (limited) / $59/mo |
| theHarvester | Email/employee harvesting | Free |
| LinkedIn | Employee intelligence | Free (manual) |
| GitHub | Code/secret exposure | Free |
| Maltego | OSINT visualization | Free (CE) / $1,500/yr |

**Recon budget:** $0-59/month

---

## Category 2: Vulnerability Scanning

| Tool | Purpose | Cost |
|------|---------|------|
| nuclei | Template-based vuln scanning | Free |
| sqlmap | SQL injection | Free |
| ffuf | Web fuzzing | Free |
| nikto | Web server scanning | Free |
| wapiti | Web app scanning | Free |
| Nessus | Enterprise vuln scanning | $0 (Essentials) / $3,490/yr |
| Qualys | Enterprise vuln scanning | Custom pricing |

**Scanning budget:** $0-3,490/year

---

## Category 3: Exploitation

| Tool | Purpose | Cost |
|------|---------|------|
| Metasploit | Exploitation framework | Free (CE) / $5,000/yr (Pro) |
| Cobalt Strike | Commercial C2 + exploitation | $5,900/year |
| Sliver | Open-source C2 | Free |
| Havoc | Open-source C2 | Free |
| Mythic | Open-source C2 | Free |
| Impacket | Windows protocol attacks | Free |
| Responder | LLMNR/NBT-NS poisoning | Free |
| CrackMapExec | Windows domain attacks | Free |
| BloodHound | AD attack path mapping | Free |
| Rubeus | Kerberos abuse | Free |
| Mimikatz | Credential dumping | Free |
| pypykatz | Python Mimikatz | Free |

**Exploitation budget:** $0-5,900/year

---

## Category 4: Social Engineering

| Tool | Purpose | Cost |
|------|---------|------|
| GoPhish | Phishing platform | Free |
| King Phisher | Phishing campaigns | Free |
| SET | Social Engineering Toolkit | Free |
| Evilginx2 | Advanced phishing (MFA bypass) | Free |
| Modlishka | Reverse proxy phishing | Free |
| SendGrid | Email sending | Free (100/day) / $20/mo |
| Mailgun | Email sending | Free (5,000/mo) |
| Lookalike domain | Phishing URL | $10-15/year |
| SSL certificate | HTTPS for phishing | Free (Let's Encrypt) |

**Social engineering budget:** $10-25/year

---

## Category 5: Post-Exploitation

| Tool | Purpose | Cost |
|------|---------|------|
| Chisel | SOCKS proxy/pivoting | Free |
| Ligolo-ng | Tunneling/pivoting | Free |
| Plink | SSH tunneling | Free |
| sshuttle | VPN over SSH | Free |
| Frida | Runtime instrumentation | Free |
| Burp Suite | HTTP proxy/interception | $0 (Community) / $449/yr (Pro) |
| Caido | HTTP proxy | Free / $35/mo (Pro) |

**Post-exploitation budget:** $0-449/year

---

## Category 6: Password Attacks

| Tool | Purpose | Cost |
|------|---------|------|
| Hashcat | GPU password cracking | Free |
| John the Ripper | Password cracking | Free |
| Hydra | Network logon cracker | Free |
| CeWL | Custom wordlist generator | Free |
| Mentalist | Password profile generator | Free |
| CrackStation | Online hash lookup | Free |

**Password budget:** $0

---

## Category 7: Reporting

| Tool | Purpose | Cost |
|------|---------|------|
| Aegis | AI-powered finding + report generation | Free (open source) |
| Dradis | Collaboration/reporting platform | Free (CE) / $6,000/yr |
| Faraday | Vulnerability management | Free / $5,000/yr |
| PlexTrac | Pentest reporting | Custom pricing |
| Ghostwriter | Pentest reporting | Free |

**Reporting budget:** $0-6,000/year

---

## Category 8: Infrastructure

| Item | Purpose | Cost |
|------|---------|------|
| VPS (Hetzner) | C2 server hosting | $5/month |
| VPS (DigitalOcean) | Redirectors | $5/month |
| Phishing domain | Social engineering URL | $10-15/year |
| SSL certificate | HTTPS for phishing | Free |
| VPN (Mullvad) | Operator anonymity | $5/month |
| Signal | Encrypted communication | Free |

**Infrastructure budget:** $15-20/month

---

## Total Cost Scenarios

### Scenario 1: Solo Bug Bounty Hunter

| Category | Monthly | Yearly |
|----------|---------|--------|
| Recon tools | $0 | $0 |
| Vulnerability scanning | $0 | $0 |
| Exploitation | $0 | $0 |
| Social engineering | $0 | $12 |
| Post-exploitation | $0 | $0 |
| Password attacks | $0 | $0 |
| Reporting (Aegis) | $0 | $0 |
| Infrastructure | $10 | $120 |
| **Total** | **$10** | **$132** |

### Scenario 2: Freelance Red Teamer

| Category | Monthly | Yearly |
|----------|---------|--------|
| Recon tools | $59 | $708 |
| Vulnerability scanning | $0 | $0 |
| Exploitation | $0 | $0 |
| Social engineering | $20 | $240 |
| Post-exploitation | $449 | $449 |
| Password attacks | $0 | $0 |
| Reporting (Aegis + Dradis) | $0 | $6,000 |
| Infrastructure | $20 | $240 |
| **Total** | **$548** | **$7,397** |

### Scenario 3: Red Team Firm (5 people)

| Category | Monthly | Yearly |
|----------|---------|--------|
| Recon tools | $295 | $3,540 |
| Vulnerability scanning | $3,490 | $3,490 |
| Exploitation (Cobalt Strike) | $5,900 | $5,900 |
| Social engineering | $200 | $2,400 |
| Post-exploitation | $449 | $449 |
| Password attacks | $0 | $0 |
| Reporting (PlexTrac) | $2,000 | $2,000 |
| Infrastructure | $200 | $2,400 |
| **Total** | **$12,334** | **$14,729** |

---

## Free Alternatives to Commercial Tools

| Commercial | Free Alternative | Trade-off |
|-----------|-----------------|-----------|
| Cobalt Strike ($5,900/yr) | Sliver (free) | Less polish, fewer features |
| Nessus ($3,490/yr) | Nuclei + Nmap (free) | More manual setup |
| Burp Suite Pro ($449/yr) | Caido (free) | Fewer extensions |
| Metasploit Pro ($5,000/yr) | Metasploit CE (free) | Limited features |
| Dradis ($6,000/yr) | Ghostwriter (free) | Less collaboration |
| Maltego ($1,500/yr) | OSINT Framework (free) | No GUI visualization |
