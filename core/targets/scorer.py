from typing import Dict


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(n)))


def score_target(metadata: Dict) -> Dict:
    # metadata keys expected: graphql, api_count, saas_prob, b2b, admin, export, multi_tenant, auth_heavy, static
    score = 0
    complexity = 0
    roi = 0
    noise = 0

    if metadata.get("graphql"):
        score += 20
        complexity += 10
        roi += 15

    api_count = int(metadata.get("api_count") or 0)
    score += min(api_count * 6, 30)  # up to 30
    complexity += min(api_count * 4, 30)
    roi += min(api_count * 5, 30)

    saas = float(metadata.get("saas_prob") or 0.0)
    if saas > 0.5:
        score += 25
        complexity += 10
        roi += 20

    if metadata.get("b2b"):
        score += 15
        roi += 10

    if metadata.get("admin"):
        score += 15
        complexity += 10
        roi += 10

    if metadata.get("export"):
        score += 10
        roi += 8

    if metadata.get("multi_tenant"):
        score += 20
        complexity += 20
        roi += 20

    if metadata.get("auth_heavy"):
        complexity += 15
        roi += 10

    if metadata.get("static"):
        noise += 40
        score -= 30

    # normalize
    quality = clamp(score)
    complexity_score = clamp(complexity)
    roi_score = clamp(roi)
    noise_level = clamp(noise)

    return {
        "quality_score": quality,
        "complexity_score": complexity_score,
        "roi_score": roi_score,
        "noise_level": noise_level,
    }
