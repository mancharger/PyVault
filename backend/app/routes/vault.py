from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import NoteCreate, VaultItemResponse, EncryptedNote, EncryptedPassword, AuditLogResponse, AuditLog, VaultItemCreate, User
from ..audit import log_event
from .auth import get_current_user

router = APIRouter()

# ----------------- NOTES -----------------

@router.post("/notes/", response_model=VaultItemResponse)
def create_note(note: VaultItemCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    db_note = EncryptedNote(
        user_id=current_user.id,
        ciphertext=note.ciphertext,
        iv=note.iv,
        salt=note.salt
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    
    log_event(db, client_ip, f"USER_{current_user.id}_CREATED_NOTE_{db_note.id}")
    return db_note

@router.get("/notes/", response_model=List[VaultItemResponse])
def get_notes(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    notes = db.query(EncryptedNote).filter(EncryptedNote.user_id == current_user.id).all()
    log_event(db, client_ip, f"USER_{current_user.id}_ACCESSED_NOTES")
    
    return notes


# ----------------- PASSWORDS -----------------

@router.post("/passwords/", response_model=VaultItemResponse)
def create_password(pw: VaultItemCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    db_pw = EncryptedPassword(
        user_id=current_user.id,
        ciphertext=pw.ciphertext,
        iv=pw.iv,
        salt=pw.salt
    )
    db.add(db_pw)
    db.commit()
    db.refresh(db_pw)
    
    log_event(db, client_ip, f"USER_{current_user.id}_CREATED_PASSWORD_{db_pw.id}")
    return db_pw

@router.get("/passwords/", response_model=List[VaultItemResponse])
def get_passwords(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    passwords = db.query(EncryptedPassword).filter(EncryptedPassword.user_id == current_user.id).all()
    log_event(db, client_ip, f"USER_{current_user.id}_ACCESSED_PASSWORDS")
    
    return passwords


# ----------------- AUDIT -----------------

@router.get("/audit/", response_model=List[AuditLogResponse])
def get_audit_logs(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    log_event(db, client_ip, f"USER_{current_user.id}_ACCESSED_AUDIT_LOGS")
    
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    return logs
