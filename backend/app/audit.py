import hashlib
import json
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from .models import AuditLog

def calculate_hash(previous_hash: str, timestamp: str, ip_address: str, action: str) -> str:
    """
    Calculates the SHA-256 hash for an audit log entry.
    Includes the previous hash to create an unbreakable cryptographic chain.
    """
    data = f"{previous_hash}|{timestamp}|{ip_address}|{action}"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def log_event(db: Session, ip_address: str, action: str) -> AuditLog:
    """
    Logs an event into the audit trail.
    Verifies the previous hash, calculates the new hash, and inserts the record.
    """
    # Find the last log entry to get the previous hash
    last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous_hash = last_log.transaction_hash if last_log else "0" * 64

    # Current UTC timestamp in ISO format
    # Use timezone-aware datetime for precise logging
    timestamp_now = datetime.now(timezone.utc)
    timestamp_str = timestamp_now.isoformat()

    new_hash = calculate_hash(previous_hash, timestamp_str, ip_address, action)

    new_log = AuditLog(
        timestamp=timestamp_now,
        ip_address=ip_address,
        action=action,
        transaction_hash=new_hash,
        previous_hash=previous_hash
    )
    
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    
    return new_log

def verify_chain(db: Session) -> bool:
    """
    Utility function to verify the integrity of the audit chain.
    Returns True if intact, False if tampered.
    """
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    
    expected_previous_hash = "0" * 64
    
    for log in logs:
        if log.previous_hash != expected_previous_hash:
            return False
            
        calculated = calculate_hash(
            log.previous_hash, 
            log.timestamp.isoformat(), 
            log.ip_address, 
            log.action
        )
        
        if log.transaction_hash != calculated:
            return False
            
        expected_previous_hash = log.transaction_hash
        
    return True
