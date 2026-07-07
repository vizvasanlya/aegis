# Blue Team Tools

---

## Detection and Monitoring

| Tool | Category | Cost | Purpose |
|------|----------|------|---------|
| Splunk | SIEM | $$$$ | Enterprise log analysis |
| Elastic SIEM | SIEM | Free (basic) | Open source SIEM |
| Wazuh | SIEM + EDR | Free | Open source security platform |
| CrowdStrike | EDR | $5-10/endpoint/yr | Endpoint protection |
| Microsoft Defender | EDR | Included M365 | Endpoint protection |
| Suricata | IDS/IPS | Free | Network intrusion detection |
| Zeek | Network Monitor | Free | Protocol analysis |
| Snort | IDS | Free | Signature-based detection |

## Prevention and Hardening

| Tool | Category | Cost | Purpose |
|------|----------|------|---------|
| Cloudflare | WAF + CDN | Free (basic) | Web application firewall |
| ModSecurity | WAF | Free | Apache/Nginx WAF |
| Fail2Ban | Brute Force Protection | Free | IP banning |
| OSSEC | HIDS | Free | Host intrusion detection |
| CIS Benchmarks | Hardening Guide | Free | System hardening standards |

## Forensics and Investigation

| Tool | Category | Cost | Purpose |
|------|----------|------|---------|
| Velociraptor | Endpoint Forensics | Free | Incident response |
| Autopsy | Disk Forensics | Free | Disk image analysis |
| Volatility | Memory Forensics | Free | RAM analysis |
| Wireshark | Packet Analysis | Free | Network forensics |
| YARA | Malware Detection | Free | Pattern matching |

## Vulnerability Management

| Tool | Category | Cost | Purpose |
|------|----------|------|---------|
| OpenVAS | Vulnerability Scanner | Free | Network vulnerability scanning |
| Trivy | Container Scanning | Free | Container image scanning |
| Dependabot | Dependency Scanning | Free | GitHub dependency updates |
| Snyk | Dependency Scanning | Free (basic) | Vulnerability monitoring |

## Automation and SOAR

| Tool | Category | Cost | Purpose |
|------|----------|------|---------|
| TheHive | Incident Tracking | Free | Case management |
| Cortex | Automation | Free | Observable analysis |
| Shuffle | SOAR | Free | Security orchestration |
| Demisto (XSOAR) | SOAR | $$$$ | Enterprise automation |

## Cost Summary

| Category | Budget Option | Enterprise Option |
|----------|--------------|-------------------|
| SIEM | Wazuh (free) | Splunk ($100K+/yr) |
| EDR | OSSEC (free) | CrowdStrike ($50K+/yr) |
| Network | Suricata (free) | Palo Alto ($100K+/yr) |
| Forensics | Autopsy + Volatility (free) | EnCase ($$$$) |
| Vulnerability | OpenVAS (free) | Nessus ($3,490/yr) |
| SOAR | Shuffle (free) | XSOAR ($$$$) |
| **Total** | **$0-5K/year** | **$300K+/year** |
