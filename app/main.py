from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from .config import settings
from .db import init_db, SessionLocal, Agent, Evidence, SpendLedger, Escalation, ToolObservation, Dispute
from .core import engine
from .security import authenticate, bootstrap_env_keys
from .rate_limit import enforce
from .proxy import router as proxy_router
import httpx, socket
from urllib.parse import urlparse

app=FastAPI(title='Derviq Agent Control & Trust Engine',version='4.0.0',docs_url=None,redoc_url=None,openapi_url=None)
app.include_router(proxy_router)
@app.on_event('startup')
def startup(): init_db(); bootstrap_env_keys()
def db_dep():
    db=SessionLocal()
    try: yield db
    finally: db.close()

class Register(BaseModel):
    agent_id:str=Field(min_length=1,max_length=200); owner:str; provider:str='custom'; framework:str='agnostic'; metadata:dict=Field(default_factory=dict)
class Delegate(BaseModel): parent_id:str; child_id:str; authority:dict=Field(default_factory=dict)
class PolicyIn(BaseModel): rules:dict
class Eval(BaseModel): agent_id:str; action:str; amount:float=0; resource:str='generic'; action_id:str|None=None; context:dict=Field(default_factory=dict)
class EvidenceIn(BaseModel): agent_id:str; event_type:str; action_id:str|None=None; payload:dict=Field(default_factory=dict)
class RecoveryIn(BaseModel): action_id:str; compensation_url:str; method:str='POST'; headers:dict=Field(default_factory=dict); body:dict=Field(default_factory=dict)
class DisputeIn(BaseModel): organization_a:str; organization_b:str; action_id:str; evidence_refs:list[str]=Field(default_factory=list)
class SpendIn(BaseModel): agent_id:str; action_id:str; amount:float=Field(ge=0); resource:str='generic'; metadata:dict=Field(default_factory=dict)
class EscalateIn(BaseModel): agent_id:str; action_id:str; reason:str; metadata:dict=Field(default_factory=dict)
class EscalationResolve(BaseModel): decision:str; reviewer:str
class ToolScanIn(BaseModel): agent_id:str; tools:list[dict]=Field(default_factory=list)
class DisputeResolve(BaseModel): status:str; resolution:dict=Field(default_factory=dict)

@app.get('/health')
def health(): return {'status':'ok','mode':settings.app_env,'database':'configured','engine_version':'4.0.0','core_features':12}
@app.get('/runtime')
def runtime(): return {'status':'ok','mode':settings.app_env,'proxy':{'enabled':True,'allowlist_configured':bool(settings.proxy_upstream_allowlist),'fail_closed':settings.fail_closed},'authentication':{'required':settings.require_auth},'rate_limit_per_minute':settings.rate_limit_per_minute,'core_features':12}
@app.get('/integrations')
def integrations(auth=Depends(authenticate)): return {'cross_vendor':True,'framework_agnostic':True,'proxy':{'provider':'httpx','configured':bool(settings.proxy_upstream_allowlist),'capability':'real allowlisted HTTP forwarding'},'database':{'provider':'postgresql','configured':True}}

@app.post('/identities')
def register(x:Register,db=Depends(db_dep),auth=Depends(authenticate)):
    enforce(auth['tenant_id'])
    try: a=engine.register(db,auth['tenant_id'],x.agent_id,x.owner,x.provider,x.framework,x.metadata)
    except ValueError as e: raise HTTPException(409,str(e))
    return {'id':a.id,'agent_id':a.agent_id,'tenant_id':a.tenant_id,'provider':a.provider,'framework':a.framework,'status':a.status}
@app.post('/identities/{agent_id}/kill')
def kill(agent_id,db=Depends(db_dep),auth=Depends(authenticate)):
    try: a=engine.kill(db,auth['tenant_id'],agent_id); engine.evidence(db,auth['tenant_id'],agent_id,'AGENT_KILLED',{}); return {'status':a.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_AGENT')
@app.post('/identities/{agent_id}/degrade')
def degrade(agent_id,db=Depends(db_dep),auth=Depends(authenticate)):
    try: a=engine.degrade(db,auth['tenant_id'],agent_id); engine.evidence(db,auth['tenant_id'],agent_id,'AGENT_DEGRADED',{}); return {'status':a.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_AGENT')
@app.post('/identities/{agent_id}/activate')
def activate(agent_id,db=Depends(db_dep),auth=Depends(authenticate)):
    try: a=engine.activate(db,auth['tenant_id'],agent_id); engine.evidence(db,auth['tenant_id'],agent_id,'AGENT_ACTIVATED',{}); return {'status':a.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_AGENT')

@app.post('/delegations')
def delegate(x:Delegate,db=Depends(db_dep),auth=Depends(authenticate)):
    try: d=engine.delegate(db,auth['tenant_id'],x.parent_id,x.child_id,x.authority); return {'id':d.id,'parent':d.parent_id,'child':d.child_id,'authority':d.authority}
    except ValueError as e: raise HTTPException(400,str(e))
@app.get('/agents/{agent_id}/lineage')
def lineage(agent_id,db=Depends(db_dep),auth=Depends(authenticate)): return engine.lineage(db,auth['tenant_id'],agent_id)
@app.post('/policies/{agent_id}')
def policy(agent_id,x:PolicyIn,db=Depends(db_dep),auth=Depends(authenticate)): engine.set_policy(db,auth['tenant_id'],agent_id,x.rules); return {'saved':True,'rules':x.rules}
@app.post('/evaluate')
def evaluate(x:Eval,db=Depends(db_dep),auth=Depends(authenticate)):
    enforce(auth['tenant_id']); d=engine.evaluate(db,auth['tenant_id'],x.agent_id,x.action,x.amount,x.context,x.resource,x.action_id)
    if d.get('requires_approval') and d.get('allow'):
        eid=x.action_id or 'eval-'+str(__import__('uuid').uuid4()); e=engine.create_escalation(db,auth['tenant_id'],x.agent_id,eid,'POLICY_REQUIRES_HUMAN_APPROVAL',{'decision':d}); d['allow']=False; d['reason']='HUMAN_APPROVAL_REQUIRED'; d['escalation_id']=e.id
    return d
@app.post('/intent/verify')
def intent(x:Eval,db=Depends(db_dep),auth=Depends(authenticate)):
    d=engine.evaluate(db,auth['tenant_id'],x.agent_id,x.action,x.amount,x.context,x.resource,x.action_id)
    return {'intent_allowed':d['allow'],'authority_verified':d.get('authority',{}).get('authorized',False),'decision':d}

@app.post('/spend/reserve')
def spend_reserve(x:SpendIn,db=Depends(db_dep),auth=Depends(authenticate)):
    d=engine.evaluate(db,auth['tenant_id'],x.agent_id,'spend',x.amount,{'risk':0},x.resource,x.action_id)
    if not d['allow']: raise HTTPException(403,d)
    row=engine.reserve_spend(db,auth['tenant_id'],x.agent_id,x.action_id,x.amount,x.resource,x.metadata)
    engine.evidence(db,auth['tenant_id'],x.agent_id,'SPEND_RESERVED',{'ledger_id':row.id,'amount':x.amount,'resource':x.resource},x.action_id)
    return {'id':row.id,'status':row.status,'amount':row.amount}
@app.post('/spend/{ledger_id}/{status}')
def spend_status(ledger_id:int,status:str,db=Depends(db_dep),auth=Depends(authenticate)):
    if status not in ('committed','released','failed'): raise HTTPException(400,'INVALID_SPEND_STATUS')
    try: row=engine.set_spend_status(db,auth['tenant_id'],ledger_id,status); return {'id':row.id,'status':row.status}
    except KeyError: raise HTTPException(404,'UNKNOWN_LEDGER_ENTRY')
@app.get('/spend')
def spend_list(db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(SpendLedger).where(SpendLedger.tenant_id==auth['tenant_id']).order_by(desc(SpendLedger.id)).limit(500)))
    return [{'id':r.id,'agent_id':r.agent_id,'action_id':r.action_id,'amount':r.amount,'resource':r.resource,'status':r.status} for r in rows]

@app.post('/escalations')
def escalation(x:EscalateIn,db=Depends(db_dep),auth=Depends(authenticate)):
    e=engine.create_escalation(db,auth['tenant_id'],x.agent_id,x.action_id,x.reason,x.metadata); return {'id':e.id,'status':e.decision}
@app.get('/escalations')
def escalations(db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(Escalation).where(Escalation.tenant_id==auth['tenant_id']).order_by(desc(Escalation.id)).limit(500)))
    return [{'id':e.id,'agent_id':e.agent_id,'action_id':e.action_id,'reason':e.reason,'status':e.decision,'reviewer':e.reviewer} for e in rows]
@app.post('/escalations/{eid}/resolve')
def escalation_resolve(eid:int,x:EscalationResolve,db=Depends(db_dep),auth=Depends(authenticate)):
    try: e=engine.resolve_escalation(db,auth['tenant_id'],eid,x.decision,x.reviewer); return {'id':e.id,'status':e.decision,'reviewer':e.reviewer}
    except (KeyError,ValueError) as e: raise HTTPException(400,str(e))

@app.post('/shadow-scan')
def shadow_scan(x:ToolScanIn,db=Depends(db_dep),auth=Depends(authenticate)):
    known=[]; shadow=[]
    for item in x.tools:
        name=str(item.get('name','')).strip()
        if not name: continue
        vendor=str(item.get('vendor','unknown')); source=str(item.get('source','runtime'))
        row=engine.observe_tool(db,auth['tenant_id'],x.agent_id,name,vendor,source,item)
        known.append(row.tool_name)
        if bool(item.get('undeclared')) or source in ('runtime','network','observed') and not bool(item.get('declared',False)):
            row.status='shadow'; db.commit(); shadow.append(name)
    engine.evidence(db,auth['tenant_id'],x.agent_id,'SHADOW_TOOL_SCAN',{'observed':known,'shadow':shadow})
    return {'agent_id':x.agent_id,'observed_tools':known,'shadow_tools':shadow,'count':len(known)}
@app.get('/shadow-scan/{agent_id}')
def shadow_list(agent_id:str,db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(ToolObservation).where(ToolObservation.tenant_id==auth['tenant_id'],ToolObservation.agent_id==agent_id).order_by(desc(ToolObservation.id))))
    return [{'tool':r.tool_name,'vendor':r.vendor,'source':r.source,'status':r.status,'first_seen':r.first_seen,'last_seen':r.last_seen} for r in rows]

@app.post('/evidence')
def evidence(x:EvidenceIn,db=Depends(db_dep),auth=Depends(authenticate)):
    e=engine.evidence(db,auth['tenant_id'],x.agent_id,x.event_type,x.payload,x.action_id); return {'id':e.id,'hash':e.event_hash,'previous_hash':e.previous_hash,'signature':e.signature}
@app.get('/evidence/verify')
def verify(db=Depends(db_dep),auth=Depends(authenticate)): return engine.verify_chain(db,auth['tenant_id'])
@app.get('/evidence')
def evidence_list(db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(Evidence).where(Evidence.tenant_id==auth['tenant_id']).order_by(desc(Evidence.id)).limit(500)))
    return [{'id':e.id,'agent_id':e.agent_id,'event_type':e.event_type,'action_id':e.action_id,'hash':e.event_hash,'previous_hash':e.previous_hash,'signature':e.signature,'payload':e.payload} for e in rows]

@app.post('/recovery')
async def recovery(x:RecoveryIn,db=Depends(db_dep),auth=Depends(authenticate)):
    if not settings.proxy_upstream_allowlist: raise HTTPException(503,'RECOVERY_TARGET_ALLOWLIST_NOT_CONFIGURED')
    if not any(x.compensation_url.startswith(a.rstrip('/')+'/') or x.compensation_url==a.rstrip('/') for a in settings.proxy_upstream_allowlist.split(',') if a.strip()): raise HTTPException(403,'RECOVERY_TARGET_NOT_ALLOWLISTED')
    try:
        async with httpx.AsyncClient(timeout=settings.recovery_timeout_seconds,follow_redirects=False,trust_env=False) as c: r=await c.request(x.method,x.compensation_url,headers=x.headers,json=x.body)
        status='executed' if 200<=r.status_code<300 else 'failed'; resp={'status_code':r.status_code,'body':r.text[:4000]}
    except httpx.HTTPError as e: status='failed'; resp={'error':type(e).__name__}
    rec=engine.recover_record(db,auth['tenant_id'],x.action_id,{'url':x.compensation_url,'method':x.method,'body':x.body},resp,status)
    return {'id':rec.id,'status':status,'response':resp}

@app.post('/disputes')
def dispute(x:DisputeIn,db=Depends(db_dep),auth=Depends(authenticate)): d=engine.dispute(db,auth['tenant_id'],x.organization_a,x.organization_b,x.action_id,x.evidence_refs); return {'id':d.id,'status':d.status}
@app.get('/disputes')
def disputes(db=Depends(db_dep),auth=Depends(authenticate)):
    rows=list(db.scalars(select(Dispute).where(Dispute.tenant_id==auth['tenant_id']).order_by(desc(Dispute.id)).limit(500)))
    return [{'id':d.id,'organization_a':d.organization_a,'organization_b':d.organization_b,'action_id':d.action_id,'status':d.status,'evidence_refs':d.evidence_refs,'resolution':d.resolution} for d in rows]
@app.post('/disputes/{did}/resolve')
def dispute_resolve(did:int,x:DisputeResolve,db=Depends(db_dep),auth=Depends(authenticate)):
    try: d=engine.resolve_dispute(db,auth['tenant_id'],did,x.status,x.resolution); return {'id':d.id,'status':d.status,'resolution':d.resolution}
    except (KeyError,ValueError) as e: raise HTTPException(400,str(e))

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
