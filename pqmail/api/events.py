"""
Event queue for PQMail gateway.

The gateway (proxy.py) pushes email processing events to this queue.
The FastAPI backend (api/app.py) pulls from this queue and broadcasts to React.

Thread-safe for async operations.
"""

import asyncio
from typing import Dict, Any


# Global event queue — shared between gateway and API
event_queue: asyncio.Queue = None


def init_event_queue():
    """
    Initialize the global event queue.
    Call this once at startup before starting the gateway.
    """
    global event_queue
    if event_queue is None:
        event_queue = asyncio.Queue()


async def push_event(event: Dict[str, Any]):
    """
    Push an email processing event to the queue.

    Event schema (example):
        {
            "message_id": "<msg-12345@example.com>",
            "from": "alice@example.com",
            "to": ["bob@example.com"],
            "algorithm": "RSA",
            "risk": {
                "risk_category": "HIGH",
                "years_of_safety_remaining": 2,
                "sensitivity": "MEDIUM",
            },
            "flag": "UPGRADED",
            "timestamp": "2026-05-17T10:30:45.123456"
        }

    Args:
        event: Dict containing email metadata, risk score, and action taken
    """
    global event_queue
    if event_queue is None:
        init_event_queue()

    await event_queue.put(event)


async def get_event(timeout_sec: float = None):
    """
    Pull an event from the queue (blocking).

    Args:
        timeout_sec: Max seconds to wait, or None for no timeout

    Returns:
        Event dict, or None if timeout expired
    """
    global event_queue
    if event_queue is None:
        init_event_queue()

    try:
        if timeout_sec is None:
            return await event_queue.get()
        else:
            return await asyncio.wait_for(event_queue.get(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        return None


def get_event_queue():
    """Return reference to the global event queue."""
    global event_queue
    if event_queue is None:
        init_event_queue()
    return event_queue
