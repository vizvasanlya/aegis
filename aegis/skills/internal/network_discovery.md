---
name: network_discovery
description: Host discovery, port scanning, and service enumeration on internal networks
---

# Network Discovery

## Host Discovery

```bash
# ARP scan (works on local network segment)
nmap -sn 10.0.0.0/24 -PR

# Ping sweep (broader, but misses hosts behind firewalls)
nmap -sn 10.0.0.0/24

# Fast ping sweep
fping -a -g 10.0.0.0/24 2>/dev/null
```

## Port Scanning

```bash
# Quick scan of common ports
nmap -sV -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443,27017 TARGET

# Full port scan
nmap -sV -p- TARGET

# Service version detection
nmap -sV -sC TARGET

# OS detection
nmap -O TARGET
```

## Service Enumeration

```bash
# Enumerate SMB shares
nmap -p 445 --script smb-enum-shares,smb-enum-users TARGET

# Enumerate SNMP
nmap -sU -p 161 --script snmp-brute TARGET

# Enumerate NFS
nmap -p 2049 --script nfs-showmount TARGET
```

## Using the Tool

```python
from aegis.tools.internal.network_scan import discover_hosts, scan_ports

# Discover hosts
hosts = await discover_hosts("10.0.0.0/24")

# Scan ports
hosts = await scan_ports(hosts, ports="1-1000")
```
