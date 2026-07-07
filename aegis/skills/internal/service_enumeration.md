---
name: service_enumeration
description: Discover internal web apps, databases, admin panels, and hidden services
---

# Internal Service Enumeration

## Web Application Discovery

```bash
# Find internal web servers
nmap -p 80,443,8080,8443,3000,5000,8000,9090 10.0.0.0/24 -sV

# Brute force common paths
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.0.1.50/FUZZ -mc 200,301,302,403
```

## Database Discovery

```bash
# MySQL
nmap -p 3306 --script mysql-info 10.0.0.0/24

# PostgreSQL
nmap -p 5432 --script pgsql-brute 10.0.0.0/24

# MongoDB
nmap -p 27017 --script mongodb-info 10.0.0.0/24

# Redis
nmap -p 6379 --script redis-info 10.0.0.0/24
```

## Admin Panel Discovery

Common admin interfaces to check:

| Service | Default Port | Path |
|---------|-------------|------|
| Jenkins | 8080 | /login |
| Grafana | 3000 | /login |
| Kibana | 5601 | /app/kibana |
| Prometheus | 9090 | /graph |
| RabbitMQ | 15672 | /#/queues |
| Kubernetes | 6443 | /api |

## Message Queue Discovery

```bash
# RabbitMQ management
curl -u guest:guest http://10.0.1.50:15672/api/overview

# Kafka (check for JMX)
nmap -p 9092,9093 10.0.0.0/24
```
