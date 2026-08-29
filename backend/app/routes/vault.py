from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
import os
import uuid

from ..database import get_db
from ..models import VaultItemResponse, EncryptedNote, EncryptedPassword, AuditLogResponse, AuditLog, VaultItemCreate, User, EncryptedFileMetadata, FileMetadataResponse
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


# ----------------- FILES -----------------

@router.post("/files/upload/", response_model=FileMetadataResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    encrypted_filename: str = Form(...),
    iv: str = Form(...),
    salt: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    
    # Check file size (1MB limit)
    contents = await file.read()
    if len(contents) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (1MB limit)")
    
    # Generate unique file_id
    file_id = str(uuid.uuid4())
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    file_path = os.path.join(upload_dir, file_id)
    
    # Save encrypted blob to disk
    with open(file_path, "wb") as f:
        f.write(contents)
        
    # Save metadata to DB
    db_file = EncryptedFileMetadata(
        user_id=current_user.id,
        file_id=file_id,
        encrypted_filename=encrypted_filename,
        iv=iv,
        salt=salt
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    log_event(db, client_ip, f"USER_{current_user.id}_UPLOADED_FILE_{file_id}")
    return db_file

@router.get("/files/", response_model=List[FileMetadataResponse])
def get_files(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    files = db.query(EncryptedFileMetadata).filter(EncryptedFileMetadata.user_id == current_user.id).all()
    log_event(db, client_ip, f"USER_{current_user.id}_ACCESSED_FILES")
    return files

@router.get("/files/download/{file_id}")
def download_file(file_id: str, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    db_file = db.query(EncryptedFileMetadata).filter(EncryptedFileMetadata.file_id == file_id).first()
    if not db_file or db_file.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
        
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    file_path = os.path.join(upload_dir, file_id)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Physical file missing")
        
    log_event(db, client_ip, f"USER_{current_user.id}_DOWNLOADED_FILE_{file_id}")
    
    return FileResponse(path=file_path, media_type="application/octet-stream", filename=file_id)


# ----------------- AUDIT -----------------

@router.get("/audit/", response_model=List[AuditLogResponse])
def get_audit_logs(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    log_event(db, client_ip, f"USER_{current_user.id}_ACCESSED_AUDIT_LOGS")
    
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    return logs
