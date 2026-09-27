from datetime import datetime, timezone
import hashlib, hmac, json, uuid
from sqlalchemy import select, desc, func
from .db import Agent, Delegation, Policy, Evidence, Recovery, Dispute, SpendLedger, Escalation, ToolObservation
from .config import settings

class Engine:
    def register(self,db,tenant,agent_id,owner,provider='custom',framework='agnostic',metadata=None):
        if db.scalar(select(Agent).where(Agent.tenant_id==tenant,Agent.agent_id==agent_id)): raise ValueError('AGENT_EXISTS')
        a=Agent(tenant_id=tenant,agent_id=agent_id,owner=owner,provider=provider,framework=framework,metadata_json=metadata or {})
        db.add(a); db.commit(); db.refresh(a); return a
    def get_agent(self,db,tenant,agent_id): return db.scalar(select(Agent).where(Agent.tenant_id==tenant,Agent.agent_id==agent_id))
    def kill(self,db,tenant,agent_id):
        a=self.get_agent(db,tenant,agent_id)
        if not a: raise KeyError(agent_id)
        a.status='killed'; db.commit(); return a
    def degrade(self,db,tenant,agent_id):
        a=self.get_agent(db,tenant,agent_id)
        if not a: raise KeyError(agent_id)
        a.status='degraded'; db.commit(); return a
    def activate(self,db,tenant,agent_id):
        a=self.get_agent(db,tenant,agent_id)
        if not a: raise KeyError(agent_id)
        a.status='active'; db.commit(); return a
    def delegate(self,db,tenant,parent,child,authority):
        if parent==child: raise ValueError('SELF_DELEGATION_FORBIDDEN')
        if not self.get_agent(db,tenant,parent) or not self.get_agent(db,tenant,child): raise ValueError('UNKNOWN_AGENT')
        d=Delegation(tenant_id=tenant,parent_id=parent,child_id=child,authority=authority); db.add(d); db.commit(); db.refresh(d); return d
    def lineage(self,db,tenant,agent):
        seen=[]; cur=agent
        while cur and cur not in seen:
            seen.append(cur); d=db.scalar(select(Delegation).where(Delegation.tenant_id==tenant,Delegation.child_id==cur,Delegation.active==True))
            cur=d.parent_id if d else None
        return {'agent_id':agent,'lineage':seen,'depth':len(seen)-1}
    def set_policy(self,db,tenant,agent,rules):
        p=db.scalar(select(Policy).where(Policy.tenant_id==tenant,Policy.agent_id==agent))
        if not p: p=Policy(tenant_id=tenant,agent_id=agent); db.add(p)
        p.rules=rules; p.updated_at=datetime.now(timezone.utc); db.commit(); return p
    def _authority(self,db,tenant,agent,action):
        d=db.scalar(select(Delegation).where(Delegation.tenant_id==tenant,Delegation.child_id==agent,Delegation.active==True).order_by(desc(Delegation.id)))
        if not d: return {'authorized':True,'source':'root','parent':None}
        allowed=d.authority.get('actions') if isinstance(d.authority,dict) else None
        if allowed and action not in allowed and '*' not in allowed: return {'authorized':False,'source':'delegation','parent':d.parent_id,'reason':'ACTION_OUTSIDE_DELEGATED_AUTHORITY'}
        return {'authorized':True,'source':'delegation','parent':d.parent_id}
    def evaluate(self,db,tenant,agent,action,amount,context,resource='generic',action_id=None):
        a=self.get_agent(db,tenant,agent)
        if not a: return {'allow':False,'reason':'UNKNOWN_AGENT'}
        if a.status=='killed': return {'allow':False,'reason':'AGENT_KILLED'}
        p=db.scalar(select(Policy).where(Policy.tenant_id==tenant,Policy.agent_id==agent)); rules=(p.rules if p else {})
        risk=float(context.get('risk',0) or 0); amount=float(amount or 0)
        authority=self._authority(db,tenant,agent,action)
        if not authority['authorized']: return {'allow':False,'reason':authority['reason'],'authority':authority}
        denied=set(rules.get('deny_actions',[]))
        if action in denied: return {'allow':False,'reason':'ACTION_DENIED_BY_POLICY'}
        if rules.get('allow_actions') and action not in rules['allow_actions'] and '*' not in rules['allow_actions']: return {'allow':False,'reason':'ACTION_NOT_IN_ALLOWLIST'}
        if rules.get('max_amount') is not None and amount>float(rules['max_amount']): return {'allow':False,'reason':'AMOUNT_LIMIT_EXCEEDED'}
        if rules.get('max_risk') is not None and risk>float(rules['max_risk']): return {'allow':False,'reason':'RISK_LIMIT_EXCEEDED'}
        if a.status=='degraded' and risk>float(rules.get('degraded_max_risk',0.25)): return {'allow':False,'reason':'DEGRADED_MODE_BLOCK'}
        budget=rules.get('budget')
        if budget is not None:
            used=float(db.scalar(select(func.coalesce(func.sum(SpendLedger.amount),0)).where(SpendLedger.tenant_id==tenant,SpendLedger.agent_id==agent,SpendLedger.status.in_(['reserved','committed']))) or 0)
            if used+amount>float(budget): return {'allow':False,'reason':'BUDGET_EXCEEDED','budget':budget,'used':used}
        escalation=rules.get('escalate_if',{})
        needs_hitl=bool(escalation.get('risk_gte') is not None and risk>=float(escalation['risk_gte'])) or bool(escalation.get('amount_gte') is not None and amount>=float(escalation['amount_gte']))
        return {'allow':True,'reason':'POLICY_ALLOWED','agent_status':a.status,'authority':authority,'risk':risk,'amount':amount,'resource':resource,'requires_approval':needs_hitl,'action_id':action_id}
    def reserve_spend(self,db,tenant,agent,action_id,amount,resource,metadata=None):
        row=SpendLedger(tenant_id=tenant,agent_id=agent,action_id=action_id,amount=float(amount),resource=resource,status='reserved',metadata_json=metadata or {})
        db.add(row); db.commit(); db.refresh(row); return row
    def set_spend_status(self,db,tenant,ledger_id,status):
        row=db.scalar(select(SpendLedger).where(SpendLedger.tenant_id==tenant,SpendLedger.id==ledger_id))
        if not row: raise KeyError(ledger_id)
        row.status=status; db.commit(); return row
    def create_escalation(self,db,tenant,agent,action_id,reason,metadata=None):
        e=Escalation(tenant_id=tenant,agent_id=agent,action_id=action_id,reason=reason,metadata_json=metadata or {}); db.add(e); db.commit(); db.refresh(e); return e
    def resolve_escalation(self,db,tenant,eid,decision,reviewer):
        e=db.scalar(select(Escalation).where(Escalation.tenant_id==tenant,Escalation.id==eid))
        if not e: raise KeyError(eid)
        if decision not in ('approved','rejected'): raise ValueError('INVALID_DECISION')
        e.decision=decision; e.reviewer=reviewer; e.resolved_at=datetime.now(timezone.utc); db.commit(); return e
    def observe_tool(self,db,tenant,agent,tool,vendor,source,metadata=None):
        row=db.scalar(select(ToolObservation).where(ToolObservation.tenant_id==tenant,ToolObservation.agent_id==agent,ToolObservation.tool_name==tool))
        if not row:
            row=ToolObservation(tenant_id=tenant,agent_id=agent,tool_name=tool,vendor=vendor,source=source,metadata_json=metadata or {}); db.add(row)
        else:
            row.vendor=vendor; row.source=source; row.last_seen=datetime.now(timezone.utc); row.metadata_json=metadata or row.metadata_json
        db.commit(); db.refresh(row); return row
    def evidence(self,db,tenant,agent,event_type,payload,action_id=None):
        last=db.scalar(select(Evidence).where(Evidence.tenant_id==tenant).order_by(desc(Evidence.id)).limit(1)); prev=last.event_hash if last else ''
        canonical=json.dumps({'tenant':tenant,'agent':agent,'event_type':event_type,'action_id':action_id,'payload':payload,'previous_hash':prev},sort_keys=True,separators=(',',':'))
        h=hashlib.sha256(canonical.encode()).hexdigest(); sig=hmac.new(settings.api_secret_key.encode(),h.encode(),hashlib.sha256).hexdigest()
        e=Evidence(tenant_id=tenant,agent_id=agent,event_type=event_type,action_id=action_id,payload=payload,previous_hash=prev,event_hash=h,signature=sig); db.add(e); db.commit(); db.refresh(e); return e
    def verify_chain(self,db,tenant):
        rows=list(db.scalars(select(Evidence).where(Evidence.tenant_id==tenant).order_by(Evidence.id))) ; prev=''
        for e in rows:
            canonical=json.dumps({'tenant':tenant,'agent':e.agent_id,'event_type':e.event_type,'action_id':e.action_id,'payload':e.payload,'previous_hash':e.previous_hash},sort_keys=True,separators=(',',':'))
            expected=hashlib.sha256(canonical.encode()).hexdigest(); sig=hmac.new(settings.api_secret_key.encode(),e.event_hash.encode(),hashlib.sha256).hexdigest()
            if e.previous_hash!=prev or expected!=e.event_hash or not hmac.compare_digest(sig,e.signature or ''): return {'valid':False,'checked':e.id,'reason':'CHAIN_OR_SIGNATURE_INVALID'}
            prev=e.event_hash
        return {'valid':True,'checked':len(rows),'head':prev,'signature_algorithm':'HMAC-SHA256'}
    def recover_record(self,db,tenant,action_id,request,response,status):
        r=Recovery(tenant_id=tenant,action_id=action_id,request=request,response=response,status=status); db.add(r); db.commit(); db.refresh(r); return r
    def dispute(self,db,tenant,a,b,action,evidence_refs):
        d=Dispute(tenant_id=tenant,organization_a=a,organization_b=b,action_id=action,evidence_refs=evidence_refs); db.add(d); db.commit(); db.refresh(d); return d
    def resolve_dispute(self,db,tenant,did,status,resolution):
        d=db.scalar(select(Dispute).where(Dispute.tenant_id==tenant,Dispute.id==did))
        if not d: raise KeyError(did)
        if status not in ('resolved','rejected','escalated'): raise ValueError('INVALID_DISPUTE_STATUS')
        d.status=status; d.resolution=resolution; d.resolved_at=datetime.now(timezone.utc); db.commit(); return d
engine=Engine()
