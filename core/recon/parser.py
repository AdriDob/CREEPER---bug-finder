import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

AUTH_SMELLS = ["org_id", "tenant_id", "workspace_id", "account_id", "user_id", "team_id"]
SIGNAL_KEYWORDS = ["/api/", "/graphql", "/admin/", "/export", "/internal"]
UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
NUMERIC_PATTERN = re.compile(r"/(?:[0-9]+)(?:/|$)")


@dataclass
class EndpointMetadata:
    raw: str
    scheme: str
    host: str
    path: str
    normalized: str
    labels: list[str]
    auth_smells: list[str]
    uuid: bool
    numeric_id: bool
    score: int

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "normalized": self.normalized,
            "labels": self.labels,
            "auth_smells": self.auth_smells,
            "uuid": self.uuid,
            "numeric_id": self.numeric_id,
            "score": self.score,
        }


class EndpointParser:
    def normalize_path(self, path: str) -> str:
        parts = [segment for segment in path.split("/") if segment]
        normalized = []
        for segment in parts:
            if UUID_PATTERN.search(segment):
                normalized.append("{uuid}")
            elif segment.isdigit():
                normalized.append("{id}")
            elif re.match(r"^[0-9a-fA-F]{24}$", segment):
                normalized.append("{hex_id}")
            else:
                normalized.append(segment)
        if not normalized:
            return "/"
        return "/" + "/".join(normalized)

    def extract_path(self, raw: str) -> str:
        raw = raw.strip()
        if raw.startswith("http"):
            parsed = urlparse(raw)
            return parsed.path or "/"
        if raw.startswith("/"):
            return raw
        if "?" in raw:
            return raw.split("?", 1)[0]
        return raw

    def detect_labels(self, path: str) -> list[str]:
        labels = []
        lower = path.lower()
        for keyword in SIGNAL_KEYWORDS:
            if keyword in lower:
                labels.append(keyword.strip("/"))
        if "/graphql" in lower:
            labels.append("graphql")
        if "/admin" in lower:
            labels.append("admin")
        if "export" in lower:
            labels.append("export")
        if "internal" in lower:
            labels.append("internal")
        return sorted(set(labels))

    def detect_auth_smells(self, path: str) -> list[str]:
        smells = []
        for token in AUTH_SMELLS:
            if token in path.lower():
                smells.append(token)
        return smells

    def calculate_score(self, path: str, labels: Iterable[str], smells: Iterable[str]) -> int:
        score = 0
        if "export" in labels:
            score += 30
        if "org" in labels or "internal" in labels:
            score += 20
        if "graphql" in labels:
            score += 20
        if "admin" in labels:
            score += 20
        if any(smell in smells for smell in ["org_id", "tenant_id", "workspace_id", "account_id", "user_id", "team_id"]):
            score += 25
        if UUID_PATTERN.search(path):
            score += 25
        if NUMERIC_PATTERN.search(path):
            score += 15
        if "/import" in path.lower():
            score += 20
        if "/file" in path.lower() or ".pdf" in path.lower() or ".csv" in path.lower():
            score += 10
        return min(score, 100)

    def extract_url(self, raw: str) -> str:
        raw = raw.strip()
        if raw.startswith("{") and raw.endswith("}"):
            try:
                payload = json.loads(raw)
                for key in ["url", "uri", "link", "request", "host"]:
                    if key in payload and isinstance(payload[key], str):
                        return payload[key]
                if "url" in payload and isinstance(payload["url"], dict):
                    return payload["url"].get("raw", raw)
            except json.JSONDecodeError:
                pass
        return raw

    def parse_endpoint(self, raw: str) -> EndpointMetadata:
        raw = raw.strip()
        url = self.extract_url(raw)
        path = self.extract_path(url)
        normalized = self.normalize_path(path)
        labels = self.detect_labels(path)
        smells = self.detect_auth_smells(path)
        score = self.calculate_score(path, labels, smells)
        parsed = urlparse(url) if url.startswith("http") else urlparse("http://example.com" + path)
        return EndpointMetadata(
            raw=url,
            scheme=parsed.scheme,
            host=parsed.netloc,
            path=path,
            normalized=normalized,
            labels=labels,
            auth_smells=smells,
            uuid=bool(UUID_PATTERN.search(path)),
            numeric_id=bool(NUMERIC_PATTERN.search(path)),
            score=score,
        )

    def parse_lines(self, lines: Iterable[str]) -> list[EndpointMetadata]:
        endpoints = []
        seen = set()
        for raw in lines:
            if not raw:
                continue
            metadata = self.parse_endpoint(raw)
            hash_key = (metadata.normalized, tuple(metadata.labels), tuple(metadata.auth_smells))
            if hash_key in seen:
                continue
            seen.add(hash_key)
            endpoints.append(metadata)
        return endpoints

    def save_metadata(self, endpoints: list[EndpointMetadata], out_path: Path) -> Path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        array = [endpoint.to_dict() for endpoint in endpoints]
        out_path.write_text(json.dumps(array, indent=2))
        return out_path

    def parse_files(self, source_paths: list[Path], out_path: Path) -> Path:
        lines = []
        for path in source_paths:
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as stream:
                for raw in stream:
                    raw = raw.strip()
                    if raw:
                        lines.append(raw)
        endpoints = self.parse_lines(lines)
        return self.save_metadata(endpoints, out_path)
