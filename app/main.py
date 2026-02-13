from fastapi import FastAPI
from .keys import key_manager
from jose import jwt
import time

app = FastAPI(title="JWKS Server")

@app.get("/")
async def root():
    return {"message": "JWKS Server running on port 8080"}

@app.get("/.well-known/jwks.json")
async def get_jwks():
    return key_manager.get_unexpired_jwks()

@app.post("/auth")
async def auth_endpoint(expired: bool = False):
    now = int(time.time())
    if expired:
        key_data = key_manager.get_key('expired-1')
        exp_time = now - 60
        kid = 'expired-1'
    else:
        key_data = key_manager.get_key('active-1')
        exp_time = now + 900
        kid = 'active-1'
    
    payload = {"sub": "test-user", "exp": exp_time, "iat": now}
    token = jwt.encode(payload, key_data['private'], algorithm='RS256', headers={'kid': kid})
    return {"access_token": token, "token_type": "bearer"}
