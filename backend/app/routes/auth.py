import pyotp
import jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from passlib.hash import argon2

from ..database import get_db
from ..models import User, UserCreate, UserLogin
from ..audit import log_event

import os
import secrets

router = APIRouter()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Nao autorizado")
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token invalido")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token invalido ou expirado")
        
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario nao encontrado")
    return user

@router.post("/register")
def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        log_event(db, client_ip, f"REGISTER_FAIL_USER_EXISTS_{user_data.username}")
        raise HTTPException(status_code=400, detail="Usuario ja existe")
        
    hashed_auth = argon2.hash(user_data.auth_key)
    
    new_user = User(
        username=user_data.username,
        auth_hash=hashed_auth,
        mfa_enabled=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    log_event(db, client_ip, f"USER_REGISTERED_{new_user.id}")
    
    # Generate token immediately
    access_token = create_access_token(data={"sub": str(new_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login")
def login(user_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not argon2.verify(user_data.auth_key, user.auth_hash):
        log_event(db, client_ip, f"LOGIN_FAILED_{user_data.username}")
        raise HTTPException(status_code=401, detail="Credenciais invalidas")
        
    if user.mfa_enabled:
        if not user_data.mfa_code:
            # Tell client MFA is required
            return {"mfa_required": True}
        
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(user_data.mfa_code):
            log_event(db, client_ip, f"LOGIN_MFA_FAILED_{user.id}")
            raise HTTPException(status_code=401, detail="Codigo MFA invalido")
            
    log_event(db, client_ip, f"LOGIN_SUCCESS_{user.id}")
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/mfa/setup")
def setup_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA ja esta ativado")
        
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    db.commit()
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="PyVault")
    return {"secret": secret, "uri": uri}


@router.post("/mfa/verify")
def verify_mfa(code: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA ja esta ativado")
        
    totp = pyotp.TOTP(current_user.mfa_secret)
    if totp.verify(code.get("code")):
        current_user.mfa_enabled = True
        db.commit()
        return {"status": "MFA ativado com sucesso"}
        
    raise HTTPException(status_code=400, detail="Codigo invalido")
