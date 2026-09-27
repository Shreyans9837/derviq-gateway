import ipaddress, socket, json
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, Request, Response, Depends, HTTPException
from .config import settings
from .db import SessionLocal
from .core import engine
from .security import authenticate
from .rate_limit import enforce

router=APIRouter(prefix='/proxy',tags=['enforcement'])
HOP={'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','host','content-length'}

def allowlist(): return [x.strip().rstrip('/') for x in settings.proxy_upstream_allowlist.split(',') if x.strip()]
def target_allowed(url):
    try:
        p=urlparse(url)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.fragment: return False
        als=allowlist()
        if not als: return False if settings.fail_closed else True
        base=f'{p.scheme}://{p.netloc}{p.path or "/"}'
        return any(base==x or base.startswith(x+'/') or base.startswith(x+'?') for x in als)
    except: return False

def public_host(host):
    try:
        for info in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM):
            ip=ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast: return False
        return True
    except: return False

def clean_headers(request): return {k:v for k,v in request.headers.items() if k.lower() not in HOP and k.lower() not in {'x-api-key','x-derviq-agent','x-derviq-risk'}}

@router.api_route('/forward',methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
async def forward(request:Request, auth=Depends(authenticate)):
    tenant=auth['tenant_id']; enforce(tenant)
    agent=request.headers.get('x-derviq-agent'); url=request.query_params.get('url')
    if not agent or not url: raise HTTPException(400,'url and X-Derviq-Agent are required')
    body=await request.body()
    if len(body)>settings.max_action_body_bytes: raise HTTPException(413,'body too large')
    if not target_allowed(url): raise HTTPException(403,'TARGET_NOT_ALLOWLISTED')
    host=urlparse(url).hostname
    if not host or not public_host(host): raise HTTPException(403,'TARGET_NETWORK_NOT_ALLOWED')
    db=SessionLocal()
    try:
        risk=float(request.headers.get('x-derviq-risk','0') or 0)
        decision=engine.evaluate(db,tenant,agent,request.method.lower(),0,{'risk':risk,'target_host':host})
        if not decision['allow']:
            engine.evidence(db,tenant,agent,'ACTION_DENIED',{'method':request.method,'url':url,'reason':decision['reason']})
            raise HTTPException(403,decision)
        try:
            async with httpx.AsyncClient(timeout=settings.proxy_timeout_seconds,follow_redirects=False,trust_env=False) as client:
                up=await client.request(request.method,url,headers=clean_headers(request),content=body)
            engine.evidence(db,tenant,agent,'ACTION_EXECUTED',{'method':request.method,'url':url,'status':up.status_code})
            headers={k:v for k,v in up.headers.items() if k.lower() not in HOP}
            return Response(up.content,status_code=up.status_code,headers=headers)
        except httpx.HTTPError as e:
            engine.evidence(db,tenant,agent,'ACTION_FAILED',{'url':url,'error':type(e).__name__})
            raise HTTPException(502,'UPSTREAM_REQUEST_FAILED')
    finally: db.close()
