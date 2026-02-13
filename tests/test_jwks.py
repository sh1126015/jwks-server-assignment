import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "JWKS Server running on port 8080"

def test_jwks_endpoint():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    jwks = response.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1  # Only active key
    assert jwks["keys"][0]["kid"] == "active-1"
    assert jwks["keys"][0]["kty"] == "RSA"

def test_auth_endpoint():
    response = client.post("/auth")
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
