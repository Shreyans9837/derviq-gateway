from fastapi import FastAPI, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from .config import settings
from .db import init_db, SessionLocal, Agent, Evidence
from .core import Engine
from .security import authenticate
from .adapters.cloud import aws_status, azure_status, gcp_status
from .proxy import router as proxy_router

app=FastAPI(title="Derviq Agent Control & Trust Engine",version="2.0.0")
engine=Engine()
app.include_router(proxy_router)

@app.on_event("startup")
def startup(): init_db()

def db_dep():
    db=SessionLocal()
    try: yield db
    finally: db.close()

class Register(BaseModel):
    agent_id: str
    owner: str
    provider: str="custom"
    metadata: dict={}

class Delegate(BaseModel):
    parent_id: str
    child_id: str
    authority: dict

class PolicyIn(BaseModel):
    rules: dict

class Eval(BaseModel):
    agent_id: str
    action: str
    amount: float=0
    context: dict={}

class EvidenceIn(BaseModel):
    agent_id: str
    event_type: str
    payload: dict

class RecoveryIn(BaseModel):
    action_id: str
    details: dict

class DisputeIn(BaseModel):
    organization_a: str
    organization_b: str
    action_id: str
    evidence_refs: list[str]

@app.get("/health")
def health():
    return {"status":"ok","mode":settings.app_env,"database":"postgresql"}

@app.get("/integrations")
def integrations(_: dict=Depends(authenticate)):
    return {"aws":aws_status().__dict__,"azure":azure_status().__dict__,"gcp":gcp_status().__dict__}

@app.post("/identities")
def register(x:Register, db=Depends(db_dep), _:dict=Depends(authenticate)):
    a=engine.register(db,x.agent_id,x.owner,x.provider,x.metadata)
    return {"id":a.id,"owner":a.owner,"provider":a.provider,"status":a.status}

@app.post("/identities/{agent_id}/kill")
def kill(agent_id:str,db=Depends(db_dep),_:dict=Depends(authenticate)):
    return {"status":engine.kill(db,agent_id).status}

@app.post("/identities/{agent_id}/degrade")
def degrade(agent_id:str,db=Depends(db_dep),_:dict=Depends(authenticate)):
    return {"status":engine.degrade(db,agent_id).status}

@app.post("/delegations")
def delegate(x:Delegate,db=Depends(db_dep),_:dict=Depends(authenticate)):
    d=engine.delegate(db,x.parent_id,x.child_id,x.authority)
    return {"id":d.id,"parent":d.parent_id,"child":d.child_id}

@app.get("/agents/{agent_id}/lineage")
def lineage(agent_id:str,db=Depends(db_dep),_:dict=Depends(authenticate)):
    return engine.lineage(db,agent_id)

@app.post("/policies/{agent_id}")
def policy(agent_id:str,x:PolicyIn,db=Depends(db_dep),_:dict=Depends(authenticate)):
    engine.set_policy(db,agent_id,x.rules); return {"saved":True}

@app.post("/evaluate")
def evaluate(x:Eval,db=Depends(db_dep),_:dict=Depends(authenticate)):
    return engine.evaluate(db,x.agent_id,x.action,x.amount,x.context)

@app.post("/intent/verify")
def intent(x:Eval,db=Depends(db_dep),_:dict=Depends(authenticate)):
    decision=engine.evaluate(db,x.agent_id,x.action,x.amount,x.context)
    return {"intent_allowed":decision["allow"],"decision":decision}

@app.post("/evidence")
def evidence(x:EvidenceIn,db=Depends(db_dep),_:dict=Depends(authenticate)):
    e=engine.evidence(db,x.agent_id,x.event_type,x.payload)
    return {"id":e.id,"hash":e.event_hash,"previous_hash":e.previous_hash}

@app.get("/evidence/verify")
def verify(db=Depends(db_dep),_:dict=Depends(authenticate)):
    return engine.verify_chain(db)

@app.get("/evidence")
def evidence_list(db=Depends(db_dep),_:dict=Depends(authenticate)):
    rows=list(db.scalars(select(Evidence).order_by(Evidence.id.desc()).limit(500)))
    return [{"id":e.id,"agent_id":e.agent_id,"event_type":e.event_type,"hash":e.event_hash,"payload":e.payload} for e in rows]

@app.post("/recovery")
def recovery(x:RecoveryIn,db=Depends(db_dep),_:dict=Depends(authenticate)):
    r=engine.recover(db,x.action_id,x.details); return {"id":r.id,"status":r.status}

@app.post("/disputes")
def dispute(x:DisputeIn,db=Depends(db_dep),_:dict=Depends(authenticate)):
    d=engine.dispute(db,x.organization_a,x.organization_b,x.action_id,x.evidence_refs)
    return {"id":d.id,"status":d.status}

@app.get("/")
def ui(): return FileResponse("web/index.html")

@app.get("/ui/{path:path}")
def static_ui(path:str):
    return FileResponse("web/"+path)
