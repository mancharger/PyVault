from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import NoteCreate, NoteResponse, EncryptedNote, AuditLogResponse, AuditLog
from ..audit import log_event

router = APIRouter()

@router.post("/notes/", response_model=NoteResponse)
def create_note(note: NoteCreate, request: Request, db: Session = Depends(get_db)):
    """
    Receives an encrypted note payload from the client.
    Because of zero-knowledge, we only store the ciphertext, iv, and salt.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Store the encrypted note
    db_note = EncryptedNote(
        ciphertext=note.ciphertext,
        iv=note.iv,
        salt=note.salt
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    
    # Log the action in the forensic audit trail
    log_event(db, client_ip, f"CREATED_NOTE_ID_{db_note.id}")
    
    return db_note

@router.get("/notes/", response_model=List[NoteResponse])
def get_notes(request: Request, db: Session = Depends(get_db)):
    """
    Retrieves all encrypted notes. The server cannot decrypt them.
    The client must decrypt them locally using their derived key.
    """
    client_ip = request.client.host if request.client else "unknown"
    notes = db.query(EncryptedNote).all()
    
    # Log the access attempt
    log_event(db, client_ip, "ACCESSED_ALL_NOTES")
    
    return notes

@router.get("/audit/", response_model=List[AuditLogResponse])
def get_audit_logs(request: Request, db: Session = Depends(get_db)):
    """
    Retrieves the immutable audit trail.
    """
    client_ip = request.client.host if request.client else "unknown"
    log_event(db, client_ip, "ACCESSED_AUDIT_LOGS")
    
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    return logs
