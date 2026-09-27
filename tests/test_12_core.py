import os, tempfile

DB = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
os.environ['DATABASE_URL'] = 'sqlite:///' + DB
os.environ['API_KEYS'] = 'smoke:smoke-secret'
os.environ['API_SECRET_KEY'] = 'test-signing-secret'
os.environ['REQUIRE_AUTH'] = 'true'
os.environ['APP_ENV'] = 'test'
os.environ['PROXY_UPSTREAM_ALLOWLIST'] = 'http://127.0.0.1:9'

from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine as db_engine

Base.metadata.drop_all(db_engine)
Base.metadata.create_all(db_engine)

client = TestClient(app)
H={'X-API-Key':'smoke-secret'}
client.__enter__()


def test_12_core_endpoints():
    # 1 Identity
    r=client.post('/identities',json={'agent_id':'root-agent','owner':'test','provider':'aws','framework':'custom'},headers=H); assert r.status_code==200
    r=client.post('/identities',json={'agent_id':'child-agent','owner':'test','provider':'google','framework':'custom'},headers=H); assert r.status_code==200
    # 2 Delegation
    r=client.post('/delegations',json={'parent_id':'root-agent','child_id':'child-agent','authority':{'actions':['read','spend']}},headers=H); assert r.status_code==200
    assert client.get('/agents/child-agent/lineage',headers=H).json()['lineage']==['child-agent','root-agent']
    # 3 Policy/risk
    assert client.post('/policies/child-agent',json={'rules':{'max_risk':0.5,'max_amount':100,'allow_actions':['spend','read'],'escalate_if':{'amount_gte':50}}},headers=H).status_code==200
    r=client.post('/evaluate',json={'agent_id':'child-agent','action':'read','amount':0,'context':{'risk':0.2}},headers=H); assert r.json()['allow'] is True
    r=client.post('/evaluate',json={'agent_id':'child-agent','action':'read','amount':0,'context':{'risk':0.9}},headers=H); assert r.json()['allow'] is False
    # 4 Spend guardrails
    r=client.post('/spend/reserve',json={'agent_id':'child-agent','action_id':'a1','amount':25,'resource':'compute'},headers=H); assert r.status_code==200
    lid=r.json()['id']; assert client.post(f'/spend/{lid}/committed',headers=H).json()['status']=='committed'
    # 5 HITL
    r=client.post('/evaluate',json={'agent_id':'child-agent','action':'spend','amount':75,'context':{'risk':0.2},'action_id':'a2'},headers=H); assert r.json()['reason']=='HUMAN_APPROVAL_REQUIRED'
    eid=r.json()['escalation_id']; assert client.post(f'/escalations/{eid}/resolve',json={'decision':'approved','reviewer':'reviewer-1'},headers=H).json()['status']=='approved'
    # 6 Kill/degraded
    assert client.post('/identities/child-agent/degrade',headers=H).status_code==200
    r=client.post('/evaluate',json={'agent_id':'child-agent','action':'read','amount':0,'context':{'risk':0.8}},headers=H); assert r.json()['reason']=='RISK_LIMIT_EXCEEDED'
    assert client.post('/identities/child-agent/kill',headers=H).status_code==200
    r=client.post('/evaluate',json={'agent_id':'child-agent','action':'read','amount':0,'context':{'risk':0}},headers=H); assert r.json()['reason']=='AGENT_KILLED'
    assert client.post('/identities/child-agent/activate',headers=H).status_code==200
    # 7 Shadow scanner
    r=client.post('/shadow-scan',json={'agent_id':'child-agent','tools':[{'name':'declared-tool','vendor':'aws','source':'declared','declared':True},{'name':'shadow-tool','vendor':'unknown','source':'runtime'}]},headers=H); assert 'shadow-tool' in r.json()['shadow_tools']
    # 8/9 Evidence + verification
    r=client.post('/evidence',json={'agent_id':'child-agent','event_type':'SMOKE_TEST','payload':{'ok':True}},headers=H); assert r.status_code==200
    assert client.get('/evidence/verify',headers=H).json()['valid'] is True
    # 10 Intent/authority
    r=client.post('/intent/verify',json={'agent_id':'child-agent','action':'spend','amount':1,'context':{'risk':0.1}},headers=H); assert r.json()['authority_verified'] is True
    # 11 Recovery boundary: fail closed without allowlist
    r=client.post('/recovery',json={'action_id':'a3','compensation_url':'https://example.invalid/undo','method':'POST'},headers=H); assert r.status_code==403
    # 12 Dispute + resolution
    r=client.post('/disputes',json={'organization_a':'A','organization_b':'B','action_id':'a3','evidence_refs':['1']},headers=H); assert r.status_code==200
    did=r.json()['id']; assert client.post(f'/disputes/{did}/resolve',json={'status':'resolved','resolution':{'by':'smoke'}},headers=H).json()['status']=='resolved'
    assert client.get('/health').json()['core_features']==12


def test_authentication_is_required_and_ssrf_is_blocked():
    assert client.get('/integrations').status_code == 401
    assert client.get('/docs').status_code == 401
    r=client.post('/proxy/forward?url=http://127.0.0.1:9/',headers={**H,'X-Derviq-Agent':'child-agent'})
    assert r.status_code == 403
