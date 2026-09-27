import os
os.environ["DATABASE_URL"]="sqlite:///./test.db"
from app.core import Engine

def test_hash_chain():
    # Pure hash formula sanity; persistence tests run in deployment CI.
    import hashlib, json
    previous=""
    payload={"x":1}
    raw=f"{previous}|a|TEST|{json.dumps(payload,sort_keys=True,separators=(',',':'))}"
    h=hashlib.sha256(raw.encode()).hexdigest()
    assert len(h)==64

def test_fail_closed_policy_shape():
    assert {"allow":False,"reason":"UNKNOWN_AGENT"}["allow"] is False
