from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
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
    previous_hash = Column(String(64), nullable=False)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    # This is the hash of the Auth Key, not the Master Password itself
    auth_hash = Column(String(255), nullable=False)
    mfa_secret = Column(String(32), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    notes = relationship("EncryptedNote", back_populates="owner")
    passwords = relationship("EncryptedPassword", back_populates="owner")

class EncryptedNote(Base):
    __tablename__ = "encrypted_notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext = Column(Text, nullable=False)
    iv = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="notes")

class EncryptedPassword(Base):
    __tablename__ = "encrypted_passwords"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # The client will encrypt a JSON object containing title, username, password, url
    ciphertext = Column(Text, nullable=False)
    iv = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="passwords")

class EncryptedFileMetadata(Base):
    __tablename__ = "encrypted_file_metadata"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_id = Column(String(36), unique=True, index=True)
    encrypted_filename = Column(Text, nullable=False)
    iv = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ----------------- PYDANTIC MODELS (Input Validation/Sanitization) -----------------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    auth_key: str = Field(..., min_length=16, description="Derivacao Argon2 para autenticacao")

class UserLogin(BaseModel):
    username: str
    auth_key: str
    mfa_code: Optional[str] = None

class VaultItemCreate(BaseModel):
    ciphertext: str = Field(..., min_length=1, max_length=500000)
    iv: str = Field(..., min_length=16, max_length=100)
    salt: str = Field(..., min_length=16, max_length=100)

class VaultItemResponse(BaseModel):
    id: int
    ciphertext: str
    iv: str
    salt: str
    created_at: datetime

    class Config:
        from_attributes = True

class FileMetadataResponse(BaseModel):
    id: int
    file_id: str
    encrypted_filename: str
    iv: str
    salt: str
    created_at: datetime

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    action: str
    transaction_hash: str
    previous_hash: str

    class Config:
        from_attributes = True
