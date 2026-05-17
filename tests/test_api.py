"""Tests for PQMail FastAPI Backend."""

from pathlib import Path
import sys
import json

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from fastapi.testclient import TestClient
from pqmail.api.app import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestHealthAndStatus:
    """Tests for health check and status endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
    
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "endpoints" in data
    
    def test_status_endpoint(self, client):
        """Test status endpoint."""
        response = client.get("/status")
        assert response.status_code == 200
        data = response.json()
        assert data["gateway"] == "running"
        assert "proxy_address" in data
        assert "event_queue" in data
    
    def test_config_endpoint(self, client):
        """Test config endpoint."""
        response = client.get("/config")
        assert response.status_code == 200
        data = response.json()
        assert data["quantum_timeline_years"] == 10
        assert "supported_algorithms" in data
        assert "features" in data


class TestRecipients:
    """Tests for recipient key management endpoints."""
    
    def test_list_recipients_empty(self, client):
        """Test listing recipients (initially empty)."""
        response = client.get("/recipients")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert isinstance(data["recipients"], list)
    
    def test_import_recipient_keys(self, client):
        """Test importing recipient keys."""
        import base64
        
        # Create test keys
        mlkem_key = b"x" * 1184
        x25519_key = b"y" * 32
        
        response = client.post(
            "/recipients/alice@example.com/keys",
            json={
                "mlkem_public_key": base64.b64encode(mlkem_key).decode('ascii'),
                "x25519_public_key": base64.b64encode(x25519_key).decode('ascii'),
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "alice@example.com"
        assert data["status"] == "imported"
    
    def test_get_recipient_keys(self, client):
        """Test retrieving recipient keys."""
        import base64
        
        # First import keys
        mlkem_key = b"x" * 1184
        x25519_key = b"y" * 32
        
        client.post(
            "/recipients/bob@example.com/keys",
            json={
                "mlkem_public_key": base64.b64encode(mlkem_key).decode('ascii'),
                "x25519_public_key": base64.b64encode(x25519_key).decode('ascii'),
            }
        )
        
        # Then retrieve them
        response = client.get("/recipients/bob@example.com/keys")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "bob@example.com"
        assert "mlkem_public_key" in data
        assert "x25519_public_key" in data
        assert "imported_at" in data
    
    def test_get_nonexistent_recipient_keys(self, client):
        """Test retrieving keys for non-existent recipient."""
        response = client.get("/recipients/nonexistent@example.com/keys")
        assert response.status_code == 404
    
    def test_import_invalid_key_format(self, client):
        """Test importing with invalid key format."""
        response = client.post(
            "/recipients/test@example.com/keys",
            json={
                "mlkem_public_key": "not-valid-base64!!!",
                "x25519_public_key": "also-invalid!!!",
            }
        )
        
        assert response.status_code == 400


class TestAudit:
    """Tests for audit endpoints."""
    
    def test_audit_stats_empty(self, client):
        """Test audit stats when no audit has run."""
        response = client.get("/audit/stats")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "last_audit" in data
    
    def test_upload_non_mbox_file(self, client):
        """Test uploading non-mbox file."""
        response = client.post(
            "/audit/upload",
            files={"file": ("test.txt", b"not an mbox file", "text/plain")}
        )
        
        assert response.status_code == 400
    
    def test_upload_real_mbox_file(self, client):
        """Test uploading real .mbox file."""
        mbox_path = Path(__file__).resolve().parents[1] / "samples" / "mailbox.mbox"
        
        if not mbox_path.exists():
            pytest.skip(f"Sample mailbox not found at {mbox_path}")
        
        with open(mbox_path, "rb") as f:
            response = client.post(
                "/audit/upload",
                files={"file": ("mailbox.mbox", f, "application/mbox")}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "mailbox.mbox"
        assert "audit" in data
        assert "critical_count" in data
        assert "unencrypted_count" in data
        assert data["audit"]["total_emails"] > 0


class TestDocumentation:
    """Tests for API documentation."""
    
    def test_openapi_schema(self, client):
        """Test OpenAPI schema is available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "paths" in data
    
    def test_swagger_docs(self, client):
        """Test Swagger documentation is available."""
        response = client.get("/docs")
        assert response.status_code == 200
        assert "swagger" in response.text.lower() or "redoc" in response.text.lower()
