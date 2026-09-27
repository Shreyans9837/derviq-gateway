from fastapi import Header, HTTPException, status
from .config import settings
from .db import SessionLocal, ApiKey, Tenant, hash_key
from sqlalchemy import select

def bootstrap_env_keys():
    if not settings.api_keys: return
    db=SessionLocal()
    try:
        for item in settings.api_keys.split(','):
            if ':' not in item: continue
            tenant,key=item.split(':',1)
            if not tenant or not key: continue
            if not db.scalar(select(Tenant).where(Tenant.tenant_id==tenant)):
                db.add(Tenant(tenant_id=tenant,name=tenant)); db.commit()
            if not db.scalar(select(ApiKey).where(ApiKey.key_hash==hash_key(key))):
                db.add(ApiKey(key_hash=hash_key(key),tenant_id=tenant)); db.commit()
    finally: db.close()

def authenticate(x_api_key: str|None=Header(default=None, alias='X-API-Key')):
    if not settings.require_auth:
        return {'tenant_id':'default','authenticated':False}
    if not x_api_key: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='Missing X-API-Key')
    db=SessionLocal()
    try:
        k=db.scalar(select(ApiKey).where(ApiKey.key_hash==hash_key(x_api_key),ApiKey.active==True))
        if not k: raise HTTPException(status_code=401,detail='Invalid X-API-Key')
        return {'tenant_id':k.tenant_id,'authenticated':True}
    finally: db.close()
