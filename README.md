# JWKS Server Assignment

## Status: ✅ COMPLETE

**Endpoints Working:**
- GET /.well-known/jwks.json → Active RSA keys
- POST /auth → JWT tokens  
- Tests: 3/3 passed

**Run:** uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
