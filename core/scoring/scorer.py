from typing import Dict


class Scorer:
    def score_target(self, meta: Dict[str, bool]) -> Dict[str, float]:
        score = 0.0
        if meta.get("is_saas"):
            score += 20.0
        if meta.get("has_api"):
            score += 30.0
        if meta.get("multi_tenant"):
            score += 25.0
        if meta.get("has_admin"):
            score += 20.0
        if meta.get("has_graphql"):
            score += 20.0
        quality = min(score, 100.0)
        return {
            "priority": quality,
            "saaS_probability": 80.0 if meta.get("is_saas") else 40.0,
            "target_quality": quality,
        }

    def score_endpoint(self, endpoint_meta: Dict[str, bool]) -> Dict[str, float]:
        score = 0.0
        if endpoint_meta.get("export"):
            score += 30.0
        if endpoint_meta.get("admin"):
            score += 20.0
        if endpoint_meta.get("graphql"):
            score += 20.0
        if endpoint_meta.get("internal"):
            score += 20.0
        if endpoint_meta.get("uuid"):
            score += 25.0
        if endpoint_meta.get("numeric_id"):
            score += 15.0
        if endpoint_meta.get("auth_smell"):
            score += 25.0
        return {"priority": min(score, 100.0), "risk_score": min(score, 100.0)}
