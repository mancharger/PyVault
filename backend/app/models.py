from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from pydantic import BaseModel, constr, Field
from .database import Base
from datetime import datetime
from typing import Optional

# ----------------- SQLALCHEMY MODELS (DB Schema) -----------------

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45), nullable=False)
    action = Column(String(255), nullable=False)
    transaction_hash = Column(String(64), nullable=False)
    # The previous hash in the chain
    previous_hash = Column(String(64), nullable=False)

class EncryptedNote(Base):
    __tablename__ = "encrypted_notes"

    id = Column(Integer, primary_key=True, index=True)
    # Storing IV and Ciphertext together or separately. 
    # Usually a combined string like iv:salt:ciphertext or separated
    ciphertext = Column(Text, nullable=False)
    iv = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class EncryptedFileMetadata(Base):
    __tablename__ = "encrypted_file_metadata"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), unique=True, index=True)
    # The filename itself must be encrypted
    encrypted_filename = Column(Text, nullable=False)
    iv = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ----------------- PYDANTIC MODELS (Input Validation/Sanitization) -----------------

# OWASP Top 10 - Injection Prevention:
# We strictly limit the types, lengths, and patterns of the input.

class NoteCreate(BaseModel):
    # Base64 encoded ciphertext, iv, and salt
    ciphertext: str = Field(..., min_length=1, max_length=100000, description="Base64 encoded ciphertext")
    iv: str = Field(..., min_length=16, max_length=100, description="Base64 encoded Initialization Vector")
    salt: str = Field(..., min_length=16, max_length=100, description="Base64 encoded Salt")

class NoteResponse(BaseModel):
    id: int
    ciphertext: str
    iv: str
    salt: str
    created_at: datetime

    class Config:
        from_attributes = True

class FileMetadataCreate(BaseModel):
    encrypted_filename: str = Field(..., min_length=1, max_length=2000)
    iv: str = Field(..., min_length=16, max_length=100)
    salt: str = Field(..., min_length=16, max_length=100)

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    action: str
    transaction_hash: str
    previous_hash: str

    class Config:
        from_attributes = True
