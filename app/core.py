from datetime import datetime, timezone
import hashlib, json
from sqlalchemy import select, desc
from .db import Agent, Delegation, Policy, Evidence, Recovery, Dispute

class Engine:
    def register(self, db, tenant, agent_id, owner, provider='custom', metadata=None):
        if db.scalar(select(Agent).where(Agent.tenant_id==tenant, Agent.agent_id==agent_id)):
            raise ValueError('AGENT_EXISTS')
        a=Agent(tenant_id=tenant,agent_id=agent_id,owner=owner,provider=provider,metadata_json=metadata or {})
        db.add(a); db.commit(); db.refresh(a); return a
    def get_agent(self,db,tenant,agent_id):
        return db.scalar(select(Agent).where(Agent.tenant_id==tenant,Agent.agent_id==agent_id))
    def kill(self,db,tenant,agent_id):
        a=self.get_agent(db,tenant,agent_id)
        if not a: raise KeyError(agent_id)
        a.status='killed'; db.commit(); return a
    def degrade(self,db,tenant,agent_id):
        a=self.get_agent(db,tenant,agent_id)
        if not a: raise KeyError(agent_id)
        a.status='degraded'; db.commit(); return a
    def delegate(self,db,tenant,parent,child,authority):
        if not self.get_agent(db,tenant,parent) or not self.get_agent(db,tenant,child): raise ValueError('UNKNOWN_AGENT')
        d=Delegation(tenant_id=tenant,parent_id=parent,child_id=child,authority=authority); db.add(d); db.commit(); db.refresh(d); return d
    def lineage(self,db,tenant,agent):
        seen=[]; cur=agent
        while cur and cur not in seen:
            seen.append(cur); d=db.scalar(select(Delegation).where(Delegation.tenant_id==tenant,Delegation.child_id==cur))
            cur=d.parent_id if d else None
        return {'agent_id':agent,'lineage':seen}
    def set_policy(self,db,tenant,agent,rules):
        p=db.scalar(select(Policy).where(Policy.tenant_id==tenant,Policy.agent_id==agent))
        if not p: p=Policy(tenant_id=tenant,agent_id=agent); db.add(p)
        p.rules=rules; p.updated_at=datetime.now(timezone.utc); db.commit(); return p
    def evaluate(self,db,tenant,agent,action,amount,context):
        a=self.get_agent(db,tenant,agent)
        if not a: return {'allow':False,'reason':'UNKNOWN_AGENT'}
        if a.status=='killed': return {'allow':False,'reason':'AGENT_KILLED'}
        p=db.scalar(select(Policy).where(Policy.tenant_id==tenant,Policy.agent_id==agent))
        rules=(p.rules if p else {})
        risk=float(context.get('risk',0) or 0)
        max_amount=rules.get('max_amount')
        max_risk=rules.get('max_risk')
        denied_actions=set(rules.get('deny_actions',[]))
        if action in denied_actions: return {'allow':False,'reason':'ACTION_DENIED_BY_POLICY'}
        if max_amount is not None and amount>float(max_amount): return {'allow':False,'reason':'AMOUNT_LIMIT_EXCEEDED'}
        if max_risk is not None and risk>float(max_risk): return {'allow':False,'reason':'RISK_LIMIT_EXCEEDED'}
        if a.status=='degraded' and risk>float(rules.get('degraded_max_risk',0.25)): return {'allow':False,'reason':'DEGRADED_MODE_BLOCK'}
        return {'allow':True,'reason':'POLICY_ALLOWED','agent_status':a.status}
    def evidence(self,db,tenant,agent,event_type,payload):
        last=db.scalar(select(Evidence).where(Evidence.tenant_id==tenant).order_by(desc(Evidence.id)).limit(1))
        prev=last.event_hash if last else ''
        canonical=json.dumps({'tenant':tenant,'agent':agent,'event_type':event_type,'payload':payload,'previous_hash':prev},sort_keys=True,separators=(',',':'))
        h=hashlib.sha256(canonical.encode()).hexdigest()
        e=Evidence(tenant_id=tenant,agent_id=agent,event_type=event_type,payload=payload,previous_hash=prev,event_hash=h); db.add(e); db.commit(); db.refresh(e); return e
    def verify_chain(self,db,tenant):
        rows=list(db.scalars(select(Evidence).where(Evidence.tenant_id==tenant).order_by(Evidence.id)))
        prev=''
        for e in rows:
            canonical=json.dumps({'tenant':tenant,'agent':e.agent_id,'event_type':e.event_type,'payload':e.payload,'previous_hash':e.previous_hash},sort_keys=True,separators=(',',':'))
            if e.previous_hash!=prev or hashlib.sha256(canonical.encode()).hexdigest()!=e.event_hash: return {'valid':False,'checked':e.id}
            prev=e.event_hash
        return {'valid':True,'checked':len(rows),'head':prev}
    def recover_record(self,db,tenant,action_id,request,response,status):
        r=Recovery(tenant_id=tenant,action_id=action_id,request=request,response=response,status=status); db.add(r); db.commit(); db.refresh(r); return r
    def dispute(self,db,tenant,a,b,action,evidence_refs):
        d=Dispute(tenant_id=tenant,organization_a=a,organization_b=b,action_id=action,evidence_refs=evidence_refs); db.add(d); db.commit(); db.refresh(d); return d
engine=Engine()
