from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/auth", tags=["Authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "analyst"

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool

oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.username == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or not found"
        )
    return user

def get_optional_current_user(token: Optional[str] = Depends(oauth2_scheme_optional), db: Session = Depends(get_db)) -> Optional[User]:
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    return db.query(User).filter(User.username == payload["sub"]).first()


@router.post("/register", response_model=UserResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == req.username) | (User.email == req.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    new_user = User(
        username=req.username,
        email=req.email,
        full_name=req.full_name or req.username.capitalize(),
        hashed_password=hash_password(req.password),
        role=req.role if req.role in ["admin", "analyst", "investigator"] else "analyst"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit = AuditLog(
        user_id=new_user.id,
        action="USER_REGISTER",
        resource_type="USER",
        resource_id=str(new_user.id),
        details=f"User {new_user.username} registered with role {new_user.role}"
    )
    db.add(audit)
    db.commit()

    return new_user

@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter((User.username == req.username) | (User.email == req.username)).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username/email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="User account is disabled")

    access_token = create_access_token(data={"sub": user.username, "role": user.role, "uid": user.id})
    
    audit = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=str(user.id),
        details=f"User {user.username} logged in successfully"
    )
    db.add(audit)
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/seed")
def seed_default_accounts(db: Session = Depends(get_db)):
    created = []
    if not db.query(User).filter(User.username == "admin").first():
        admin = User(
            username="admin",
            email="admin@forensics.local",
            full_name="Chief Forensic Officer",
            hashed_password=hash_password("Admin@2026!"),
            role="admin"
        )
        db.add(admin)
        created.append("admin")

    if not db.query(User).filter(User.username == "analyst").first():
        analyst = User(
            username="analyst",
            email="analyst@forensics.local",
            full_name="SOC Threat Analyst",
            hashed_password=hash_password("Analyst@2026!"),
            role="analyst"
        )
        db.add(analyst)
        created.append("analyst")

    db.commit()
    return {"status": "success", "seeded_users": created}

from app.core.config import settings
from app.services.gmail_service import get_google_auth_url, exchange_code_for_tokens, get_google_user_profile

class GoogleCallbackRequest(BaseModel):
    code: str

@router.get("/google/url")
def google_auth_url():
    return {"url": get_google_auth_url(), "client_id": settings.GOOGLE_CLIENT_ID}

@router.post("/google/callback")
def google_auth_callback(payload: GoogleCallbackRequest, db: Session = Depends(get_db)):
    try:
        tokens = exchange_code_for_tokens(payload.code)
        access_token = tokens.get("access_token")
        profile = get_google_user_profile(access_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    email = profile.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Unable to retrieve email from Google profile")
    
    username = email.split("@")[0]
    user = db.query(User).filter((User.email == email) | (User.username == username)).first()
    if not user:
        user = User(
            username=username,
            email=email,
            full_name=profile.get("name") or username.capitalize(),
            hashed_password=hash_password(settings.SESSION_SECRET[:12]),
            role="analyst"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    
    jwt_token = create_access_token(data={"sub": user.username, "role": user.role, "uid": user.id})
    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "picture": profile.get("picture")
        },
        "google_access_token": access_token
    }

