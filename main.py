import os
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import uuid

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()

app = FastAPI()

# --------------------
# Database Model
# --------------------

class NoteDB(Base):
    __tablename__ = "notes"

    id = Column(String, primary_key=True, index=True)
    title = Column(String)
    content = Column(Text)
    updated = Column(DateTime)

Base.metadata.create_all(bind=engine)

# --------------------
# Pydantic Schema
# --------------------

class Note(BaseModel):
    title: str
    content: str

# --------------------
# Routes
# --------------------

@app.get("/")
def root():
    return {"message": "Cloud Notes API running"}

@app.get("/notes")
def get_notes():
    db = SessionLocal()
    notes = db.query(NoteDB).all()
    db.close()
    return notes

@app.post("/notes")
def create_note(note: Note):
    db = SessionLocal()

    note_id = str(uuid.uuid4())

    db_note = NoteDB(
        id=note_id,
        title=note.title,
        content=note.content,
        updated=datetime.utcnow()
    )

    db.add(db_note)
    db.commit()
    db.close()

    return {"id": note_id}

@app.put("/notes/{note_id}")
def update_note(note_id: str, note: Note):
    db = SessionLocal()

    db_note = db.query(NoteDB).filter(NoteDB.id == note_id).first()

    if db_note:
        db_note.title = note.title
        db_note.content = note.content
        db_note.updated = datetime.utcnow()
        db.commit()

    db.close()
    return {"status": "updated"}

@app.delete("/notes/{note_id}")
def delete_note(note_id: str):
    db = SessionLocal()

    db_note = db.query(NoteDB).filter(NoteDB.id == note_id).first()

    if db_note:
        db.delete(db_note)
        db.commit()

    db.close()
    return {"status": "deleted"}
