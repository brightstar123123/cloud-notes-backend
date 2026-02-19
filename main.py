import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

from sqlalchemy import (
    create_engine,
    Column,
    String,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# =========================================================
# SECURITY CONFIG
# =========================================================

SECRET_KEY = "CHANGE_THIS_TO_RANDOM_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =========================================================
# DATABASE
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()

# =========================================================
# DATABASE MODELS
# =========================================================

class UserDB(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    notes = relationship("NoteDB", back_populates="owner")


class NoteDB(Base):
    __tablename__ = "notes"

    id = Column(String, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)
    created = Column(DateTime, default=datetime.utcnow)
    updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner_id = Column(String, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="notes")


# Create tables
Base.metadata.create_all(bind=engine)

# =========================================================
# Pydantic Schemas
# =========================================================

class Note(BaseModel):
    title: str
    content: str


# =========================================================
# AUTH HELPERS
# =========================================================

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    expire = datetime.utcnow() + (
        expires_delta if expires_delta else timedelta(minutes=15)
    )

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    db.close()

    if user is None:
        raise credentials_exception

    return user


# =========================================================
# ROUTES
# =========================================================

@app.get("/")
def root():
    return {"message": "Cloud Notes API running"}


# ------------------------
# AUTH ROUTES
# ------------------------

@app.post("/register")
def register(email: str, password: str):
    db = SessionLocal()

    existing_user = db.query(UserDB).filter(UserDB.email == email).first()

    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserDB(
        id=str(uuid.uuid4()),
        email=email,
        hashed_password=hash_password(password),
    )

    db.add(user)
    db.commit()
    db.close()

    return {"message": "User created"}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()

    user = db.query(UserDB).filter(UserDB.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    db.close()

    return {"access_token": access_token, "token_type": "bearer"}


# ------------------------
# NOTES ROUTES (PROTECTED)
# ------------------------

@app.get("/notes")
def get_notes(current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()

    notes = (
        db.query(NoteDB)
        .filter(NoteDB.owner_id == current_user.id)
        .order_by(NoteDB.updated.desc())
        .all()
    )

    db.close()
    return notes


@app.post("/notes")
def create_note(note: Note, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()

    db_note = NoteDB(
        id=str(uuid.uuid4()),
        title=note.title,
        content=note.content,
        owner_id=current_user.id,
    )

    db.add(db_note)
    db.commit()
    db.close()

    return {"message": "Note created"}


@app.put("/notes/{note_id}")
def update_note(note_id: str, note: Note, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()

    db_note = (
        db.query(NoteDB)
        .filter(NoteDB.id == note_id, NoteDB.owner_id == current_user.id)
        .first()
    )

    if not db_note:
        db.close()
        raise HTTPException(status_code=404, detail="Note not found")

    db_note.title = note.title
    db_note.content = note.content
    db_note.updated = datetime.utcnow()

    db.commit()
    db.close()

    return {"message": "Note updated"}


@app.delete("/notes/{note_id}")
def delete_note(note_id: str, current_user: UserDB = Depends(get_current_user)):
    db = SessionLocal()

    db_note = (
        db.query(NoteDB)
        .filter(NoteDB.id == note_id, NoteDB.owner_id == current_user.id)
        .first()
    )

    if not db_note:
        db.close()
        raise HTTPException(status_code=404, detail="Note not found")

    db.delete(db_note)
    db.commit()
    db.close()

    return {"message": "Note deleted"}
