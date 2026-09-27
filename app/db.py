from datetime import datetime, timezone
import hashlib
from sqlalchemy import create_engine, String, Integer, Float, Boolean, DateTime, UniqueConstraint, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.types import JSON
from .config import settings

class Base(DeclarativeBase): pass
engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

now=lambda: datetime.now(timezone.utc)

class Tenant(Base):
    __tablename__='tenants'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), unique=True, index=True)
    name: Mapped[str]=mapped_column(String(200))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ApiKey(Base):
    __tablename__='api_keys'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    key_hash: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    active: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Agent(Base):
    __tablename__='agents'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    owner: Mapped[str]=mapped_column(String(300))
    provider: Mapped[str]=mapped_column(String(100), default='custom')
    framework: Mapped[str]=mapped_column(String(100), default='agnostic')
    status: Mapped[str]=mapped_column(String(30), default='active')
    metadata_json: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(UniqueConstraint('tenant_id','agent_id'),)

class Delegation(Base):
    __tablename__='delegations'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    parent_id: Mapped[str]=mapped_column(String(200), index=True)
    child_id: Mapped[str]=mapped_column(String(200), index=True)
    authority: Mapped[dict]=mapped_column(JSON, default=dict)
    active: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(UniqueConstraint('tenant_id','parent_id','child_id'),)

class Policy(Base):
    __tablename__='policies'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    rules: Mapped[dict]=mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(UniqueConstraint('tenant_id','agent_id'),)

class SpendLedger(Base):
    __tablename__='spend_ledger'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    action_id: Mapped[str]=mapped_column(String(200), index=True)
    amount: Mapped[float]=mapped_column(Float, default=0)
    resource: Mapped[str]=mapped_column(String(100), default='generic')
    status: Mapped[str]=mapped_column(String(40), default='reserved')
    metadata_json: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Escalation(Base):
    __tablename__='escalations'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    action_id: Mapped[str]=mapped_column(String(200), index=True)
    reason: Mapped[str]=mapped_column(String(300))
    decision: Mapped[str]=mapped_column(String(40), default='pending')
    requested_by: Mapped[str]=mapped_column(String(200), default='system')
    reviewer: Mapped[str|None]=mapped_column(String(200), nullable=True)
    metadata_json: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    resolved_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)

class ToolObservation(Base):
    __tablename__='tool_observations'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    tool_name: Mapped[str]=mapped_column(String(200))
    vendor: Mapped[str]=mapped_column(String(120), default='unknown')
    source: Mapped[str]=mapped_column(String(300), default='declared')
    first_seen: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    status: Mapped[str]=mapped_column(String(40), default='observed')
    metadata_json: Mapped[dict]=mapped_column(JSON, default=dict)
    __table_args__=(UniqueConstraint('tenant_id','agent_id','tool_name'),)

class Evidence(Base):
    __tablename__='evidence'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    agent_id: Mapped[str]=mapped_column(String(200), index=True)
    event_type: Mapped[str]=mapped_column(String(100))
    action_id: Mapped[str|None]=mapped_column(String(200), nullable=True, index=True)
    payload: Mapped[dict]=mapped_column(JSON, default=dict)
    previous_hash: Mapped[str]=mapped_column(String(64), default='')
    event_hash: Mapped[str]=mapped_column(String(64), index=True)
    signature: Mapped[str|None]=mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(Index('ix_evidence_tenant_id_id','tenant_id','id'),)

class Recovery(Base):
    __tablename__='recoveries'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    action_id: Mapped[str]=mapped_column(String(200), index=True)
    status: Mapped[str]=mapped_column(String(40))
    request: Mapped[dict]=mapped_column(JSON, default=dict)
    response: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Dispute(Base):
    __tablename__='disputes'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str]=mapped_column(String(120), index=True)
    organization_a: Mapped[str]=mapped_column(String(200))
    organization_b: Mapped[str]=mapped_column(String(200))
    action_id: Mapped[str]=mapped_column(String(200))
    evidence_refs: Mapped[list]=mapped_column(JSON, default=list)
    status: Mapped[str]=mapped_column(String(40), default='open')
    resolution: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    resolved_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)


def init_db(): Base.metadata.create_all(engine)
def hash_key(key:str)->str: return hashlib.sha256(key.encode()).hexdigest()
