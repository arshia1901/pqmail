#!/usr/bin/env python
"""
Launch PQMail FastAPI Backend Server.

Starts the backend on http://localhost:8000
- API documentation: http://localhost:8000/docs
- OpenAPI schema: http://localhost:8000/openapi.json
"""

import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn

if __name__ == "__main__":
    print("🚀 Starting PQMail FastAPI Backend...")
    print("📍 http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("🔌 WebSocket: ws://localhost:8000/ws/events")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(
        "pqmail.api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )
