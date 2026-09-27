import time
from collections import defaultdict, deque
from threading import Lock
from fastapi import HTTPException
from .config import settings
_events=defaultdict(deque); lock=Lock()
def enforce(tenant):
    now=time.time(); cutoff=now-60
    with lock:
        q=_events[tenant]
        while q and q[0]<cutoff: q.popleft()
        if len(q)>=settings.rate_limit_per_minute: raise HTTPException(429,'RATE_LIMIT_EXCEEDED')
        q.append(now)
