from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ai.analysis import AIAnalyzer
from core.analysis.analyzer import EndpointAnalyzer
from core.recon.runner import ReconRunner
from core.scoring.scorer import Scorer
from database import db, models

app = FastAPI(title="Rastro", version="0.2")


def get_db():
    db_obj = db.SessionLocal()
    try:
        yield db_obj
    finally:
        db_obj.close()


class TargetCreate(BaseModel):
    name: str
    domain: str | None = None
    mode: str | None = "FAST"


class EndpointCreate(BaseModel):
    target_id: int
    path: str
    method: str = "GET"
    params: dict | None = None


class FindingCreate(BaseModel):
    target_id: int
    endpoint_id: int | None = None
    title: str
    severity: str | None = "medium"
    description: str | None = None


class EndpointAnalysisRequest(BaseModel):
    path: str
    method: str = "GET"
    params: dict | None = None
    model: str | None = None


@app.on_event("startup")
async def startup_event():
    db.init_db()


@app.get("/")
async def root():
    return {"message": "Rastro backend inicializado"}


@app.post("/targets")
async def create_target(target: TargetCreate, session: Session = Depends(get_db)):
    db_target = models.Target(name=target.name, domain=target.domain)
    session.add(db_target)
    session.commit()
    session.refresh(db_target)
    return {"id": db_target.id, "name": db_target.name, "domain": db_target.domain, "mode": target.mode}


@app.get("/targets")
async def list_targets(session: Session = Depends(get_db)):
    targets = session.query(models.Target).all()
    return [{"id": t.id, "name": t.name, "domain": t.domain} for t in targets]


@app.get("/targets/{target_id}/summary")
async def target_summary(target_id: int, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    endpoints = session.query(models.Endpoint).filter(models.Endpoint.target_id == target.id).all()
    analyzer = EndpointAnalyzer()
    entries = []
    for endpoint in endpoints:
        try:
            params = eval(endpoint.params or "{}")
        except Exception:
            params = {}
        metadata = analyzer.classify_endpoint(endpoint.path, endpoint.method, params)
        entries.append({
            "path": endpoint.path,
            "method": endpoint.method,
            "labels": metadata.get("labels", []),
        })
    score = Scorer().score_target({
        "is_saas": bool(target.domain),
        "has_api": any("api" in item.get("labels", []) for item in entries),
        "multi_tenant": any("org" in item.get("labels", []) or "tenant" in item.get("labels", []) for item in entries),
        "has_admin": any("admin" in item.get("labels", []) for item in entries),
        "has_graphql": any("graphql" in item.get("labels", []) for item in entries),
    })
    return {"target": {"id": target.id, "name": target.name, "domain": target.domain}, "endpoints": entries, "score": score}


@app.post("/analysis/endpoint")
async def analyze_endpoint(request: EndpointAnalysisRequest):
    analyzer = EndpointAnalyzer()
    local = analyzer.classify_endpoint(request.path, request.method, request.params or {})
    result = {"local": local}
    try:
        ai = AIAnalyzer()
        result["ai"] = ai.analyze_endpoint(request.path, request.method, request.params or {})
    except Exception as exc:
        result["ai_error"] = str(exc)
    return result


@app.post("/endpoints")
async def create_endpoint(endpoint: EndpointCreate, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == endpoint.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db_endpoint = models.Endpoint(
        target_id=endpoint.target_id,
        path=endpoint.path,
        method=endpoint.method,
        params=str(endpoint.params) if endpoint.params else None,
    )
    session.add(db_endpoint)
    session.commit()
    session.refresh(db_endpoint)
    return {
        "id": db_endpoint.id,
        "target_id": db_endpoint.target_id,
        "path": db_endpoint.path,
        "method": db_endpoint.method,
    }


@app.get("/endpoints")
async def list_endpoints(session: Session = Depends(get_db)):
    endpoints = session.query(models.Endpoint).all()
    return [
        {
            "id": e.id,
            "target_id": e.target_id,
            "path": e.path,
            "method": e.method,
            "params": e.params,
        }
        for e in endpoints
    ]


@app.post("/findings")
async def create_finding(finding: FindingCreate, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == finding.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if finding.endpoint_id:
        endpoint = session.query(models.Endpoint).filter(models.Endpoint.id == finding.endpoint_id).first()
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
    db_finding = models.Finding(
        target_id=finding.target_id,
        endpoint_id=finding.endpoint_id,
        title=finding.title,
        severity=finding.severity,
        description=finding.description,
    )
    session.add(db_finding)
    session.commit()
    session.refresh(db_finding)
    return {"id": db_finding.id, "title": db_finding.title, "severity": db_finding.severity}


@app.get("/findings")
async def list_findings(session: Session = Depends(get_db)):
    findings = session.query(models.Finding).all()
    return [
        {
            "id": f.id,
            "target_id": f.target_id,
            "endpoint_id": f.endpoint_id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
        }
        for f in findings
    ]


@app.post("/scans")
async def launch_scan(target: TargetCreate, session: Session = Depends(get_db)):
    import asyncio
    import json
    from datetime import datetime

    # ensure target exists
    db_target = session.query(models.Target).filter(models.Target.name == target.name).first()
    if not db_target:
        db_target = models.Target(name=target.name, domain=target.domain)
        session.add(db_target)
        session.commit()
        session.refresh(db_target)

    # create scan run record
    scan = models.ScanRun(target_id=db_target.id, mode=target.mode or "FAST", status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    runner = ReconRunner(Path("./targets") / target.name)
    outputs = {}
    try:
        timeout = int(__import__("os").environ.get("SCAN_TIMEOUT", "600"))
        outputs = await asyncio.wait_for(runner.run_pipeline(target.domain or target.name, mode=target.mode or "FAST"), timeout=timeout)
        # attempt to persist normalized endpoints into DB
        normalized_path = outputs.get("normalized_endpoints")
        endpoint_count = 0
        if normalized_path:
            try:
                with open(normalized_path, "r", encoding="utf-8", errors="ignore") as fh:
                    entries = json.load(fh)
                for entry in entries:
                    path = entry.get("normalized") or entry.get("path") or entry.get("raw")
                    method = "GET"
                    # avoid duplicates
                    exists = session.query(models.Endpoint).filter(models.Endpoint.target_id == db_target.id, models.Endpoint.path == path, models.Endpoint.method == method).first()
                    if exists:
                        continue
                    params_meta = {"labels": entry.get("labels"), "score": entry.get("score"), "raw": entry.get("raw"), "host": entry.get("host")}
                    db_ep = models.Endpoint(target_id=db_target.id, path=path, method=method, params=str(params_meta))
                    session.add(db_ep)
                    endpoint_count += 1
                session.commit()
            except Exception:
                # non-fatal: continue
                endpoint_count = 0

        # update scan record
        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        scan.endpoint_count = endpoint_count
        try:
            scan.outputs = json.dumps(outputs)
        except Exception:
            scan.outputs = str(outputs)
        session.add(scan)
        session.commit()
    except asyncio.TimeoutError:
        scan.status = "timeout"
        scan.finished_at = datetime.utcnow()
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as exc:
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        scan.outputs = str(exc)
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=500, detail=str(exc))

    return {"target": target.name, "mode": target.mode, "outputs": outputs}


@app.get("/digest")
async def daily_digest(session: Session = Depends(get_db)):
    analyzer = EndpointAnalyzer()
    scorer = Scorer()
    entries = []
    endpoints = session.query(models.Endpoint).all()
    for endpoint in endpoints:
        try:
            params = eval(endpoint.params or "{}")
        except Exception:
            params = {}
        labels = analyzer.classify_endpoint(endpoint.path, endpoint.method, params).get("labels", [])
        endpoint_score = scorer.score_endpoint({
            "export": "export" in labels,
            "admin": "admin" in labels,
            "graphql": "graphql" in labels,
            "internal": "internal" in labels,
            "uuid": "uuid" in endpoint.path.lower() or endpoint.path.lower().find("uuid") != -1,
            "numeric_id": any(part.isdigit() for part in endpoint.path.split("/")),
            "auth_smell": any(smell in endpoint.path.lower() for smell in ["org_id", "tenant_id", "workspace_id", "account_id", "user_id", "team_id"]),
        })
        entries.append({
            "id": endpoint.id,
            "target_id": endpoint.target_id,
            "path": endpoint.path,
            "method": endpoint.method,
            "labels": labels,
            "risk_score": endpoint_score["risk_score"],
        })
    entries.sort(key=lambda item: item["risk_score"], reverse=True)
    return {"high_signal": entries[:20]}
