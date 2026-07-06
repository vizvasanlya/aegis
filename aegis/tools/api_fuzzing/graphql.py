"""GraphQL introspection and vulnerability testing."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import requests


logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""


@dataclass
class GraphQLField:
    name: str
    type_name: str
    args: list[dict[str, str]]
    is_mutation: bool = False


@dataclass
class GraphQLSchema:
    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    types: list[dict[str, Any]] = field(default_factory=list)
    fields: list[GraphQLField] = field(default_factory=list)
    raw: dict[str, Any] | None = None


def introspect(url: str, headers: dict[str, str] | None = None) -> GraphQLSchema | None:
    """Run introspection query against a GraphQL endpoint."""
    try:
        resp = requests.post(
            url,
            json={"query": _INTROSPECTION_QUERY},
            headers=headers or {"Content-Type": "application/json"},
            timeout=30,
            verify=False,
        )

        if resp.status_code != 200:
            logger.debug("Introspection returned status %d", resp.status_code)
            return None

        data = resp.json()
        schema_data = data.get("data", {}).get("__schema")
        if not schema_data:
            return None

        schema = GraphQLSchema(
            query_type=schema_data.get("queryType", {}).get("name"),
            mutation_type=schema_data.get("mutationType", {}).get("name"),
            subscription_type=schema_data.get("subscriptionType", {}).get("name"),
            types=schema_data.get("types", []),
            raw=schema_data,
        )

        # Extract fields from query and mutation types
        for t in schema_data.get("types", []):
            if t.get("name") in ("__Schema", "__Type", "__Field", "__InputValue", "__EnumValue", "__Directive"):
                continue
            if t.get("kind") not in ("OBJECT",):
                continue

            is_mutation = t["name"] == schema.mutation_type
            for field_data in t.get("fields", []):
                args = [
                    {"name": a["name"], "type": _type_name(a.get("type", {}))}
                    for a in field_data.get("args", [])
                ]
                schema.fields.append(
                    GraphQLField(
                        name=field_data["name"],
                        type_name=t["name"],
                        args=args,
                        is_mutation=is_mutation,
                    )
                )

        logger.info(
            "GraphQL introspection: %d fields, query=%s, mutation=%s",
            len(schema.fields),
            schema.query_type,
            schema.mutation_type,
        )
        return schema

    except Exception as exc:
        logger.debug("Introspection failed: %s", exc)
        return None


def _type_name(type_ref: dict) -> str:
    """Extract readable type name from GraphQL type reference."""
    if type_ref.get("name"):
        return type_ref["name"]
    of_type = type_ref.get("ofType")
    if of_type:
        return _type_name(of_type)
    return "Unknown"


def generate_introspection_tests(url: str, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Generate tests for GraphQL introspection vulnerabilities."""
    tests = []

    # Test 1: Introspection enabled
    tests.append({
        "name": "GraphQL Introspection Enabled",
        "query": _INTROSPECTION_QUERY,
        "description": "Check if introspection is enabled (information disclosure)",
        "category": "info_disclosure",
        "severity": "medium",
    })

    # Test 2: Introspection with field suggestions
    tests.append({
        "name": "GraphQL Field Suggestion Attack",
        "query": '{"query": "{ __type(name: \\"User\\") { fields { name } } }"}',
        "description": "Check if type names leak via field suggestions",
        "category": "info_disclosure",
        "severity": "low",
    })

    # Test 3: Query batching (rate limit bypass)
    batch = [{"query": "{ __typename }"} for _ in range(10)]
    tests.append({
        "name": "GraphQL Query Batching",
        "query": json.dumps(batch),
        "description": "Send batched queries to bypass rate limiting",
        "category": "auth",
        "severity": "medium",
    })

    # Test 4: Nested query depth DoS
    deep_query = "{ " + "a { " * 50 + "__typename" + " }" * 50 + " }"
    tests.append({
        "name": "GraphQL Nested Query Depth DoS",
        "query": json.dumps({"query": deep_query}),
        "description": "Test nested query depth limit (memory exhaustion)",
        "category": "dos",
        "severity": "high",
    })

    # Test 5: Mutation without auth
    tests.append({
        "name": "GraphQL Mutation Auth Bypass",
        "query": '{"query": "mutation { createUser(input: {name: \\"test\\", email: \\"test@test.com\\"}) { id } }"}',
        "description": "Test if mutations work without authentication",
        "category": "auth",
        "severity": "critical",
    })

    return tests


def test_introspection(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Full introspection test suite."""
    schema = introspect(url, headers)

    if not schema:
        return {
            "success": True,
            "introspection_enabled": False,
            "message": "Introspection is disabled or endpoint is not GraphQL",
            "vulnerabilities": [],
        }

    vulns = []

    # Introspection enabled = info disclosure
    vulns.append({
        "title": "GraphQL Introspection Enabled",
        "severity": "medium",
        "description": (
            f"GraphQL introspection is enabled at {url}. "
            f"Schema exposes {len(schema.fields)} fields across "
            f"query type '{schema.query_type}' and mutation type '{schema.mutation_type}'. "
            "Attackers can enumerate the entire API structure."
        ),
        "cwe": "CWE-200",
        "category": "info_disclosure",
        "evidence": f"Query types: {schema.query_type}, Mutation types: {schema.mutation_type}, Total fields: {len(schema.fields)}",
    })

    # List exposed mutations
    mutations = [f for f in schema.fields if f.is_mutation]
    if mutations:
        mutation_names = [f.name for f in mutations[:20]]
        vulns.append({
            "title": f"GraphQL Mutations Exposed ({len(mutations)} total)",
            "severity": "high" if any(
                m.lower() in ("createuser", "deleteuser", "updaterole", "grantadmin", "resetpassword")
                for m in mutation_names
            ) else "medium",
            "description": f"Mutations available: {', '.join(mutation_names)}",
            "cwe": "CWE-284",
            "category": "auth",
            "evidence": f"Mutations: {json.dumps(mutation_names)}",
        })

    return {
        "success": True,
        "introspection_enabled": True,
        "query_type": schema.query_type,
        "mutation_type": schema.mutation_type,
        "total_fields": len(schema.fields),
        "mutations_count": len(mutations),
        "vulnerabilities": vulns,
    }
