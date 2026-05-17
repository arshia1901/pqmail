"""
MBOX Reader for PQMail Auditor.

Reads RFC 4155 .mbox files and extracts individual email messages.
"""

from pathlib import Path
from mailbox import mbox as mailbox_mbox
from typing import Iterator, Tuple


class MboxReader:
    """Read emails from RFC 4155 .mbox format files."""
    
    def __init__(self, mbox_path: str):
        """Initialize reader with path to .mbox file."""
        self.mbox_path = Path(mbox_path)
        
        if not self.mbox_path.exists():
            raise FileNotFoundError(f"MBOX file not found: {self.mbox_path}")
        
        if not self.mbox_path.is_file():
            raise ValueError(f"Path is not a file: {self.mbox_path}")
    
    def read_all(self) -> Iterator[Tuple[str, bytes]]:
        """
        Read all emails from the mbox file.
        
        Yields:
            Tuples of (message_id, raw_bytes) for each email
        """
        try:
            mbox_file = mailbox_mbox(str(self.mbox_path))
            
            for msg_key, msg in mbox_file.items():
                try:
                    # Extract raw email bytes
                    msg_bytes = msg.as_bytes()
                    
                    # Try to get message-id for identification
                    msg_id = msg.get("Message-ID", f"key_{msg_key}")
                    
                    yield (msg_id, msg_bytes)
                except Exception as e:
                    # Skip emails that can't be converted to bytes
                    print(f"Warning: Skipped email key {msg_key}: {e}")
                    continue
            
            mbox_file.close()
        except Exception as e:
            raise RuntimeError(f"Failed to read mbox file {self.mbox_path}: {e}")
    
    def count_messages(self) -> int:
        """Count total messages in mbox file."""
        try:
            mbox_file = mailbox_mbox(str(self.mbox_path))
            count = len(mbox_file)
            mbox_file.close()
            return count
        except Exception as e:
            raise RuntimeError(f"Failed to count messages: {e}")
    
    def get_file_size_mb(self) -> float:
        """Get mbox file size in megabytes."""
        return self.mbox_path.stat().st_size / (1024 * 1024)
