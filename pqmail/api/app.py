"""
FastAPI Backend for PQMail.

REST API and WebSocket server for the dashboard.
Provides status endpoints, configuration, and real-time event streaming.
"""

from fastapi import FastAPI, WebSocket, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, List

from pqmail.auditor.batch_scorer import BatchScorer
from pqmail.api.events import (
    init_event_queue,
    get_event,
    get_event_queue,
)


# Global state
active_connections: List[WebSocket] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup: Initialize event queue
    init_event_queue()
    print("✓ Event queue initialized")
    
    # Start event broadcaster task
    async def broadcast_events():
        """Continuously read from event queue and broadcast to WebSocket clients."""
        while True:
            try:
                event = await get_event(timeout_sec=1)
                if event:
                    # Broadcast to all connected WebSocket clients
                    for connection in active_connections[:]:
                        try:
                            await connection.send_json(event)
                        except Exception:
                            # Client disconnected
                            active_connections.remove(connection)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error in broadcast_events: {e}")
                await asyncio.sleep(0.1)
    
    # Start broadcaster as background task
    broadcaster_task = asyncio.create_task(broadcast_events())
    
    yield
    
    # Shutdown
    broadcaster_task.cancel()
    print("✓ Event broadcaster stopped")


# Create FastAPI app
app = FastAPI(
    title="PQMail Backend",
    description="Post-quantum secure email gateway API",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REST Endpoints
# ============================================================================

@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "pqmail-backend",
        "version": "0.1.0",
    }


@app.get("/config")
async def get_config() -> dict:
    """Get gateway configuration."""
    return {
        "quantum_timeline_years": 10,
        "supported_algorithms": [
            "RSA",
            "ECDH",
            "HYBRID (ML-KEM-768 + X25519)",
        ],
        "features": {
            "email_parsing": True,
            "sensitivity_classification": True,
            "risk_scoring": True,
            "hybrid_encryption": True,
        },
    }


@app.get("/status")
async def get_status() -> dict:
    """Get current gateway status."""
    return {
        "gateway": "running",
        "proxy_address": "localhost:1025",
        "upstream_smtp": "smtp.gmail.com:587",
        "event_queue": "initialized",
        "connected_clients": len(active_connections),
    }


@app.post("/audit/upload")
async def upload_mailbox(file: UploadFile = File(...)) -> dict:
    """
    Upload and audit an mbox file.
    
    Returns audit statistics.
    """
    if not file.filename.endswith('.mbox'):
        raise HTTPException(status_code=400, detail="File must be .mbox format")
    
    # Save uploaded file to system temp directory (Windows + Linux compatible)
    temp_dir = Path(tempfile.gettempdir())
    temp_path = temp_dir / file.filename
    try:
        contents = await file.read()
        temp_path.write_bytes(contents)
        
        # Score the mailbox
        scorer = BatchScorer(str(temp_path), quantum_timeline=10)
        stats = await scorer.score_all()
        
        return {
            "filename": file.filename,
            "audit": stats.to_dict(),
            "critical_count": stats.risk_categories.get("CRITICAL", 0),
            "unencrypted_count": len(scorer.get_results_by_algorithm("UNENCRYPTED")),
        }
    finally:
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()


@app.get("/audit/stats")
async def get_audit_stats() -> dict:
    """
    Get statistics from last audit run.
    (Would query database in production)
    """
    return {
        "last_audit": None,
        "message": "No audit data available. Upload an mbox file to audit.",
    }


@app.get("/recipients")
async def list_recipients() -> dict:
    """List recipients with stored keys."""
    from pqmail.keys.key_manager import KeyManager
    
    km = KeyManager()
    recipients = km.list_recipients()
    
    return {
        "total": len(recipients),
        "recipients": recipients,
    }


@app.get("/recipients/{email}/keys")
async def get_recipient_keys(email: str) -> dict:
    """Get public keys for a recipient."""
    from pqmail.keys.key_manager import KeyManager
    
    km = KeyManager()
    keys = km.get_keys(email)
    
    if not keys:
        raise HTTPException(status_code=404, detail=f"No keys for {email}")
    
    import base64
    return {
        "email": keys.email,
        "mlkem_public_key": base64.b64encode(keys.mlkem_public_key).decode('ascii'),
        "x25519_public_key": base64.b64encode(keys.x25519_public_key).decode('ascii'),
        "imported_at": keys.imported_at,
    }


@app.post("/recipients/{email}/keys")
async def import_recipient_keys(email: str, request_body: dict) -> dict:
    """Import public keys for a recipient."""
    from pqmail.keys.key_manager import KeyManager
    import base64
    
    try:
        mlkem_pub = base64.b64decode(request_body.get("mlkem_public_key", ""))
        x25519_pub = base64.b64decode(request_body.get("x25519_public_key", ""))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid key format: {e}")
    
    km = KeyManager()
    km.store_keys(email, mlkem_pub, x25519_pub)
    
    return {
        "email": email,
        "status": "imported",
    }


@app.post("/push_event")
async def receive_event(event: dict) -> dict:
    """
    Receive an email processing event from the SMTP gateway.
    
    The gateway pushes events via HTTP POST when it processes an email.
    This endpoint adds the event to the queue for broadcasting to React.
    """
    from pqmail.api.events import push_event as queue_push_event
    
    try:
        await queue_push_event(event)
        return {"status": "received", "message_id": event.get("message_id")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to queue event: {e}")


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.
    
    Clients connect and receive real-time events from the email gateway:
    - Parsed emails
    - Classification results
    - Risk scores
    - Re-encryption status
    
    Event schema:
    {
        "timestamp": "ISO8601",
        "message_id": "str",
        "from": "email",
        "to": ["email"],
        "algorithm": "RSA|ECDH|HYBRID|UNENCRYPTED|...",
        "sensitivity": "LOW|MEDIUM|HIGH|CRITICAL",
        "risk": {
            "risk_category": "CRITICAL|HIGH|MEDIUM|LOW",
            "years_of_safety_remaining": int,
        },
        "action": "UPGRADE|FORWARD|FLAG",
        "flag": "reason if flagged",
    }
    """
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        # Keep connection alive
        while True:
            # Receive messages (for future control commands)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Echo back for keep-alive
                await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                # Send keep-alive ping
                await websocket.send_json({"type": "ping"})
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


# ============================================================================
# Root
# ============================================================================

@app.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "service": "PQMail Backend",
        "documentation": "/docs",
        "openapi": "/openapi.json",
        "endpoints": {
            "health": "GET /health",
            "status": "GET /status",
            "config": "GET /config",
            "websocket": "WS /ws/events",
            "audit": "POST /audit/upload",
            "recipients": "GET /recipients",
        },
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "pqmail.api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
