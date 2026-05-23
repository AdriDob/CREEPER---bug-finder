from typing import Dict, Iterable


class EndpointAnalyzer:
    """Endpoint intelligence and auth analysis utilities."""

    def classify_endpoint(self, path: str, method: str, params: Dict[str, str]) -> Dict[str, str]:
        labels = ["api"] if "/api/" in path or path.startswith("api") or path.endswith("graphql") else ["web"]
        if "graphql" in path.lower():
            labels.append("graphql")
        if any(token in path.lower() for token in ["export", "download", "admin", "user", "org", "tenant"]):
            labels.append("sensitive")
        if any(token in path.lower() for token in ["login", "auth", "session", "token", "password"]):
            labels.append("auth")
        if params:
            if any(param.lower() in ["id", "user_id", "org_id", "tenant_id", "account_id"] for param in params.keys()):
                labels.append("id-parameter")
        return {"path": path, "method": method, "labels": ",".join(labels)}

    def synthesize_target_meta(self, endpoints: Iterable[Dict[str, str]]) -> Dict[str, bool]:
        has_api = False
        has_graphql = False
        has_admin = False
        multi_tenant = False
        for endpoint in endpoints:
            path = endpoint.get("path", "").lower()
            if "/api/" in path or path.startswith("api"):
                has_api = True
            if "graphql" in path:
                has_graphql = True
            if "admin" in path or "dashboard" in path:
                has_admin = True
            if any(token in path for token in ["org", "tenant", "company", "account"]):
                multi_tenant = True
        return {
            "has_api": has_api,
            "has_graphql": has_graphql,
            "has_admin": has_admin,
            "multi_tenant": multi_tenant,
        }
