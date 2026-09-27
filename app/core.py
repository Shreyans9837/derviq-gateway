import hashlib, json
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .db import Agent, Delegation, Policy, Evidence, Recovery, Dispute

class Engine:
    def register(self, db: Session, agent_id, owner, provider="custom", metadata=None):
        a = db.get(Agent, agent_id)
        if a:
            return a
        a = Agent(id=agent_id, owner=owner, provider=provider, metadata=metadata or {})
        db.add(a); db.commit(); db.refresh(a)
        return a

    def delegate(self, db, parent_id, child_id, authority):
        d = Delegation(parent_id=parent_id, child_id=child_id, authority=authority)
        db.add(d); db.commit(); db.refresh(d)
        return d

    def lineage(self, db, agent_id):
        out=[]; cur=agent_id
        seen=set()
        while cur and cur not in seen:
            seen.add(cur)
            row=db.scalar(select(Delegation).where(Delegation.child_id==cur))
            if not row: break
            out.append({"parent":row.parent_id,"child":row.child_id,"authority":row.authority})
            cur=row.parent_id
        return list(reversed(out))

    def set_policy(self, db, agent_id, rules):
        p=Policy(agent_id=agent_id, rules=rules)
        db.merge(p); db.commit()
        return p

    def evaluate(self, db, agent_id, action, amount=0, context=None):
        a=db.get(Agent, agent_id)
        if not a: return {"allow":False,"reason":"UNKNOWN_AGENT"}
        if a.status=="KILLED": return {"allow":False,"reason":"HARD_KILLED"}
        if a.status=="DEGRADED" and action not in {"read","health","evidence"}:
            return {"allow":False,"reason":"DEGRADED_MODE"}
        p=db.get(Policy, agent_id)
        rules=p.rules if p else {}
        blocked=set(rules.get("blocked_actions",[]))
        max_spend=float(rules.get("max_spend", 0))
        if action in blocked: return {"allow":False,"reason":"POLICY_BLOCK"}
        if max_spend and amount>max_spend: return {"allow":False,"reason":"SPEND_LIMIT"}
        required_risk=float(rules.get("max_risk", 1))
        risk=float((context or {}).get("risk",0))
        if risk>required_risk: return {"allow":False,"reason":"RISK_LIMIT"}
        return {"allow":True,"reason":"POLICY_ALLOW"}

    def evidence(self, db, agent_id, event_type, payload):
        prev=db.scalars(select(Evidence).order_by(Evidence.id.desc())).first()
        previous=prev.event_hash if prev else ""
        canonical=json.dumps(payload,sort_keys=True,separators=(",",":"))
        raw=f"{previous}|{agent_id}|{event_type}|{canonical}"
        h=hashlib.sha256(raw.encode()).hexdigest()
        e=Evidence(agent_id=agent_id,event_type=event_type,payload=payload,previous_hash=previous,event_hash=h)
        db.add(e); db.commit(); db.refresh(e)
        return e

    def verify_chain(self, db):
        rows=list(db.scalars(select(Evidence).order_by(Evidence.id)))
        prev=""
        for e in rows:
            raw=f"{prev}|{e.agent_id}|{e.event_type}|{json.dumps(e.payload,sort_keys=True,separators=(',',':'))}"
            if hashlib.sha256(raw.encode()).hexdigest()!=e.event_hash or e.previous_hash!=prev:
                return {"valid":False,"broken_id":e.id}
            prev=e.event_hash
        return {"valid":True,"events":len(rows),"head":prev}

    def kill(self,db,agent_id):
        a=db.get(Agent,agent_id)
        if not a: raise KeyError(agent_id)
        a.status="KILLED"; db.commit(); return a

    def degrade(self,db,agent_id):
        a=db.get(Agent,agent_id)
        if not a: raise KeyError(agent_id)
        a.status="DEGRADED"; db.commit(); return a

    def recover(self,db,action_id,details):
        r=Recovery(action_id=action_id,details=details)
        db.add(r); db.commit(); db.refresh(r); return r

    def dispute(self,db,a,b,action_id,evidence_refs):
        d=Dispute(organization_a=a,organization_b=b,action_id=action_id,evidence_refs=evidence_refs)
        db.add(d); db.commit(); db.refresh(d); return d
