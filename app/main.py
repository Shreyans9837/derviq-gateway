from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from .config import settings
from .db import init_db, SessionLocal, Agent, Evidence
from .core import engine
from .security import authenticate, bootstrap_env_keys
from .rate_limit import enforce
from .proxy import router as proxy_router
import httpx
from urllib.parse import urlparse

app=FastAPI(title='Derviq Agent Control & Trust Engine',version='3.0.0',docs_url=None,redoc_url=None,openapi_url=None)
app.include_router(proxy_router)
@app.on_event('startup')
def startup(): init_db(); bootstrap_env_keys()
def db_dep():
    db=SessionLocal()
    try: yield db
    finally: db.close()
class Register(BaseModel): agent_id:str=Field(min_length=1,max_length=200); owner:str; provider:str='custom'; metadata:dict={}
class Delegate(BaseModel): parent_id:str; child_id:str; authority:dict={}
class PolicyIn(BaseModel): rules:dict={}
class Eval(BaseModel): agent_id:str; action:str; amount:float=0; context:dict={}
class EvidenceIn(BaseModel): agent_id:str; event_type:str; payload:dict={}
class RecoveryIn(BaseModel): action_id:str; compensation_url:str; method:str='POST'; headers:dict={}; body:dict={}
class DisputeIn(BaseModel): organization_a:str; organization_b:str; action_id:str; evidence_refs:list[str]=[]

@app.get('/health')
def health(): return {'status':'ok','mode':settings.app_env,'database':'configured'}
@app.get('/runtime')
def runtime(): return {'status':'ok','mode':settings.app_env,'proxy':{'enabled':True,'allowlist_configured':bool(settings.proxy_upstream_allowlist),'fail_closed':settings.fail_closed},'authentication':{'required':settings.require_auth},'rate_limit_per_minute':settings.rate_limit_per_minute}
@app.get('/integrations')
def integrations(auth=Depends(authenticate)): return {'proxy':{'provider':'httpx','configured':bool(settings.proxy_upstream_allowlist),'capability':'real allowlisted HTTP forwarding'},'database':{'provider':'postgresql','configured':True}}
@app.post('/identities')
def register(x:Register,db=Depends(db_dep),auth=Depends(authenticate)):
    enforce(auth['tenant_id'])
    try: a=engine.register(db,auth['tenant_id'],x.agent_id,x.owner,x.provider,x.metadata)
    except ValueError as e: raise HTTPException(409,str(e))
    return {'id':a.id,'agent_id':a.agent_id,'tenant_id':a.tenant_id,'status':a.status}
@app.post('/identities/{agent_id}/kill')
def kill(agent_id,db=Depends(db_dep),auth=Depends(authenticate)):
    try: a=engine.kill(db,auth['tenant_id'],agent_id); engine.evidence(db,auth['tenant_id'],agent_id,'AGENT_KILLED',{}); return {'status':a.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_AGENT')
@app.post('/identities/{agent_id}/degrade')
def degrade(agent_id,db=Depends(db_dep),auth=Depends(authenticate)):
    try: a=engine.degrade(db,auth['tenant_id'],agent_id); engine.evidence(db,auth['tenant_id'],agent_id,'AGENT_DEGRADED',{}); return {'status':a.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_AGENT')
@app.post('/delegations')
def delegate(x:Delegate,db=Depends(db_dep),auth=Depends(authenticate)):
    try: d=engine.delegate(db,auth['tenant_id'],x.parent_id,x.child_id,x.authority); return {'id':d.id,'parent':d.parent_id,'child':d.child_id}
    except ValueError as e: raise HTTPException(400,str(e))
@app.get('/agents/{agent_id}/lineage')
def lineage(agent_id,db=Depends(db_dep),auth=Depends(authenticate)): return engine.lineage(db,auth['tenant_id'],agent_id)
@app.post('/policies/{agent_id}')
def policy(agent_id,x:PolicyIn,db=Depends(db_dep),auth=Depends(authenticate)): engine.set_policy(db,auth['tenant_id'],agent_id,x.rules); return {'saved':True}
@app.post('/evaluate')
def evaluate(x:Eval,db=Depends(db_dep),auth=Depends(authenticate)): enforce(auth['tenant_id']); return engine.evaluate(db,auth['tenant_id'],x.agent_id,x.action,x.amount,x.context)
@app.post('/intent/verify')
def intent(x:Eval,db=Depends(db_dep),auth=Depends(authenticate)): d=engine.evaluate(db,auth['tenant_id'],x.agent_id,x.action,x.amount,x.context); return {'intent_allowed':d['allow'],'decision':d}
@app.post('/evidence')
def evidence(x:EvidenceIn,db=Depends(db_dep),auth=Depends(authenticate)): e=engine.evidence(db,auth['tenant_id'],x.agent_id,x.event_type,x.payload); return {'id':e.id,'hash':e.event_hash,'previous_hash':e.previous_hash}
@app.get('/evidence/verify')
def verify(db=Depends(db_dep),auth=Depends(authenticate)): return engine.verify_chain(db,auth['tenant_id'])
@app.get('/evidence')
def evidence_list(db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(Evidence).where(Evidence.tenant_id==auth['tenant_id']).order_by(desc(Evidence.id)).limit(500)))
    return [{'id':e.id,'agent_id':e.agent_id,'event_type':e.event_type,'hash':e.event_hash,'previous_hash':e.previous_hash,'payload':e.payload} for e in rows]
@app.post('/recovery')
async def recovery(x:RecoveryIn,db=Depends(db_dep),auth=Depends(authenticate)):
    # Real compensating HTTP transaction. Universal rollback is impossible without target-specific semantics.
    if not settings.proxy_upstream_allowlist: raise HTTPException(503,'RECOVERY_TARGET_ALLOWLIST_NOT_CONFIGURED')
    p=urlparse(x.compensation_url)
    if not any(x.compensation_url.startswith(a.rstrip('/')+'/') or x.compensation_url==a.rstrip('/') for a in settings.proxy_upstream_allowlist.split(',') if a.strip()): raise HTTPException(403,'RECOVERY_TARGET_NOT_ALLOWLISTED')
    try:
        async with httpx.AsyncClient(timeout=settings.recovery_timeout_seconds,follow_redirects=False,trust_env=False) as c:
            r=await c.request(x.method,x.compensation_url,headers=x.headers,json=x.body)
        status='executed' if 200<=r.status_code<300 else 'failed'
        resp={'status_code':r.status_code,'body':r.text[:4000]}
    except httpx.HTTPError as e: status='failed'; resp={'error':type(e).__name__}
    rec=engine.recover_record(db,auth['tenant_id'],x.action_id,{'url':x.compensation_url,'method':x.method,'body':x.body},resp,status)
    return {'id':rec.id,'status':status,'response':resp}
@app.post('/disputes')
def dispute(x:DisputeIn,db=Depends(db_dep),auth=Depends(authenticate)): d=engine.dispute(db,auth['tenant_id'],x.organization_a,x.organization_b,x.action_id,x.evidence_refs); return {'id':d.id,'status':d.status}
@app.get('/openapi.json',include_in_schema=False)
def openapi_json(auth=Depends(authenticate)): return app.openapi()
@app.get('/docs',include_in_schema=False)
def docs(auth=Depends(authenticate)): return get_swagger_ui_html(openapi_url='/openapi.json',title='Derviq API')
@app.get('/')
def ui(): return FileResponse('web/index.html')
@app.get('/ui/{path:path}')
def static_ui(path):
    if '..' in path: raise HTTPException(400,'invalid path')
    return FileResponse('web/'+path)
