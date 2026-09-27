import httpx, json
from fastapi import APIRouter, Request, Response
from .config import settings
from .db import SessionLocal
from .core import Engine

router=APIRouter(prefix="/proxy",tags=["enforcement"])
engine=Engine()

def allowed_target(url):
    allow=[x.strip() for x in settings.proxy_upstream_allowlist.split(",") if x.strip()]
    return any(url.startswith(prefix) for prefix in allow)

@router.api_route("/forward", methods=["GET","POST","PUT","PATCH","DELETE"])
async def forward(request: Request):
    body=await request.body()
    if len(body)>settings.max_action_body_bytes:
        return Response("body too large",status_code=413)
    url=request.query_params.get("url")
    agent=request.headers.get("x-derviq-agent")
    if not url or not agent:
        return Response("url and x-derviq-agent are required",status_code=400)
    if not allowed_target(url):
        return Response("TARGET_NOT_ALLOWLISTED",status_code=403)
    db=SessionLocal()
    try:
        action=request.method.lower()
        decision=engine.evaluate(db,agent,action,context={"risk":0})
        if not decision["allow"]:
            engine.evidence(db,agent,"ACTION_DENIED",{"method":request.method,"url":url,"reason":decision["reason"]})
            return Response(json.dumps(decision),status_code=403,media_type="application/json")
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.request(request.method,url,headers={"content-type":request.headers.get("content-type","application/json")},content=body)
        engine.evidence(db,agent,"ACTION_EXECUTED",{"method":request.method,"url":url,"status":r.status_code})
        return Response(r.content,status_code=r.status_code,headers={"content-type":r.headers.get("content-type","application/octet-stream")})
    finally:
        db.close()
