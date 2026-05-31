"""
FastAPI Backend for PQMail.

REST API and WebSocket server for the dashboard.
Provides status endpoints, configuration, and real-time event streaming.
"""

from fastapi import FastAPI, WebSocket, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
import asyncio
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from pqmail.auditor.batch_scorer import BatchScorer
from pqmail.api.events import (
    init_event_queue,
    get_event,
    get_event_queue,
)


# Global state
active_connections: List[WebSocket] = []
email_storage: Dict[str, dict] = {}  # Store emails by message_id for manual re-encryption


# ============================================================================
# Pydantic Models
# ============================================================================

class UpgradeRequest(BaseModel):
    message_id: str
    recipient_email: str


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
async def receive_event(event: Dict = Body(...)) -> dict:
    """
    Receive an email processing event from the SMTP gateway.
    
    The gateway pushes events via HTTP POST when it processes an email.
    This endpoint adds the event to the queue for broadcasting to React,
    and stores the original email for manual re-encryption.
    """
    from pqmail.api.events import push_event as queue_push_event
    import base64
    import sys
    
    try:
        print(f"[API] Received event: {event.get('message_id', 'unknown')}", file=sys.stderr)
        
        # Store email for manual re-encryption via /upgrade endpoint
        message_id = event.get("message_id", "unknown")
        raw_bytes_b64 = event.get("raw_bytes_b64", "")
        
        if raw_bytes_b64:
            try:
                raw_bytes = base64.b64decode(raw_bytes_b64)
                email_storage[message_id] = {
                    "raw_bytes": raw_bytes,
                    "algorithm": event.get("algorithm", "UNKNOWN"),
                    "from": event.get("from", "unknown"),
                    "to": event.get("to", []),
                    "timestamp": event.get("timestamp", ""),
                }
                print(f"[API] Stored email {message_id} ({len(raw_bytes)} bytes)", file=sys.stderr)
            except Exception as e:
                print(f"[API] Failed to store email {message_id}: {e}", file=sys.stderr)
        else:
            print(f"[API] No raw_bytes_b64 in event", file=sys.stderr)
        
        # Queue event for WebSocket broadcast (without raw_bytes for efficiency)
        event_clean = {k: v for k, v in event.items() if k != "raw_bytes_b64"}
        await queue_push_event(event_clean)
        
        return {"status": "received", "message_id": message_id}
    except Exception as e:
        import traceback
        print(f"[API] Error in push_event: {e}\n{traceback.format_exc()}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"Failed to queue event: {e}")


@app.post("/upgrade")
async def upgrade_email_encryption(req: UpgradeRequest) -> dict:
    """
    Manually upgrade an email to ML-KEM-768 hybrid encryption.
    
    Phase 4: Actual re-encryption with re-sending to recipient.
    """
    from pqmail.parser.mime_parser import parse
    from pqmail.keys.key_manager import KeyManager
    
    message_id = req.message_id.strip()
    recipient_raw = req.recipient_email.strip()
    
    # Extract just the email address in case it contains Name <email>
    import re
    email_match = re.search(r'<([^>]+)>', recipient_raw)
    if email_match:
        recipient = email_match.group(1).strip()
    else:
        recipient = recipient_raw
        
    # Check if email is stored
    if message_id not in email_storage:
        return {
            "status": "not_found",
            "message": f"Email {message_id} not found",
            "message_id": message_id,
        }
    
    stored = email_storage[message_id]
    raw_bytes = stored.get("raw_bytes")
    
    if not raw_bytes:
        return {
            "status": "error",
            "message": "Email bytes not available",
            "message_id": message_id,
        }
    
    # Check if recipient has ML-KEM keys
    km = KeyManager()
    keys = km.get_keys(recipient)
    
    if not keys:
        return {
            "status": "no_keys",
            "message": f"No ML-KEM keys for {recipient}",
            "message_id": message_id,
        }
    
    # Check if already hybrid
    if stored.get("algorithm") == "HYBRID":
        return {
            "status": "already_hybrid",
            "message": "Already hybrid encrypted",
            "message_id": message_id,
        }
    
    try:
        # Parse the original email and use re_encrypt_message
        parsed = await parse(raw_bytes)
        from pqmail.crypto.hybrid_kem import re_encrypt_message
        from pqmail.gateway.forwarder import forward
        import os
        
        # Re-encrypt using Phase 4 function
        final_bytes = await re_encrypt_message(parsed, [recipient])
        
        # Forward to recipient if credentials available
        forwarded = False
        if os.getenv("UPSTREAM_USER") and os.getenv("UPSTREAM_PASSWORD"):
            try:
                from pqmail.parser.mime_parser import parse as parse_email
                forwarded_email = await parse_email(final_bytes)
                mail_from = forwarded_email.headers.get("from", "system@pqmail.local")
                config = {}
                await forward(final_bytes, mail_from, [recipient], config)
                forwarded = True
            except Exception as fwd_err:
                print(f"[API] Forward error: {fwd_err}")
        
        # Update storage with upgraded status
        email_storage[message_id]["algorithm"] = "HYBRID"
        email_storage[message_id]["upgraded"] = True
        
        return {
            "status": "upgraded",
            "message": "Upgraded to ML-KEM-768 hybrid encryption" + (" and forwarded" if forwarded else ""),
            "message_id": message_id,
        }
        
    except Exception as e:
        import traceback
        print(f"[API] Upgrade failed: {type(e).__name__}: {e}")
        print(traceback.format_exc())
        return {
            "status": "error",
            "message": f"Upgrade failed: {type(e).__name__}: {str(e)[:100]}",
            "message_id": message_id,
        }


# ============================================================================
# Debug Endpoints
# ============================================================================

@app.get("/debug/stored_emails")
async def debug_stored_emails() -> dict:
    """Debug: Show all stored emails for manual re-encryption."""
    return {
        "count": len(email_storage),
        "message_ids": list(email_storage.keys()),
        "storage": {k: {"bytes": len(v["raw_bytes"]), "algorithm": v["algorithm"], "to": v.get("to")} for k, v in email_storage.items()}
    }


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
