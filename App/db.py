from sqlalchemy import create_engine, String, Text, DateTime, Boolean, JSON, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from datetime import datetime, timezone
from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    owner: Mapped[str] = mapped_column(String(300))
    provider: Mapped[str] = mapped_column(String(100), default="custom")
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata: Mapped[dict] = mapped_column(JSON, default=dict)

class Delegation(Base):
    __tablename__ = "delegations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[str] = mapped_column(String(200))
    child_id: Mapped[str] = mapped_column(String(200))
    authority: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Policy(Base):
    __tablename__ = "policies"
    agent_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)

class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Recovery(Base):
    __tablename__ = "recoveries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50), default="REQUESTED")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

class Dispute(Base):
    __tablename__ = "disputes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_a: Mapped[str] = mapped_column(String(300))
    organization_b: Mapped[str] = mapped_column(String(300))
    action_id: Mapped[str] = mapped_column(String(200))
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(50), default="OPEN")

def init_db():
    Base.metadata.create_all(engine)
