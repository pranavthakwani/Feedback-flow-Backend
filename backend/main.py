from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, Text, Enum, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import uuid
import enum
import os

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./feedback_system.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT settings
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI app
app = FastAPI(title="Feedback System API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://feedback-flow-production.netlify.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enums
class UserRole(str, enum.Enum):
    manager = "manager"
    employee = "employee"

class SentimentType(str, enum.Enum):
    positive = "positive"
    neutral = "neutral"
    negative = "negative"

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False)
    team_id = Column(String, nullable=True)

class Feedback(Base):
    __tablename__ = "feedback"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    manager_id = Column(String, nullable=False)
    employee_id = Column(String, nullable=False)
    strengths = Column(Text, nullable=False)
    areas_to_improve = Column(Text, nullable=False)
    sentiment = Column(Enum(SentimentType), nullable=False)
    tags = Column(JSON, nullable=True, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Acknowledgment(Base):
    __tablename__ = "acknowledgments"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    feedback_id = Column(String, nullable=False)
    employee_id = Column(String, nullable=False)
    acknowledged_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: UserRole

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class FeedbackCreate(BaseModel):
    employee_id: str
    strengths: str
    areas_to_improve: str
    sentiment: SentimentType
    tags: List[str] = []

class FeedbackUpdate(BaseModel):
    strengths: Optional[str] = None
    areas_to_improve: Optional[str] = None
    sentiment: Optional[SentimentType] = None
    tags: Optional[List[str]] = None

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: UserRole
    team_id: Optional[str] = None

class FeedbackResponse(BaseModel):
    id: str
    manager_id: str
    employee_id: str
    manager_name: str
    employee_name: str
    strengths: str
    areas_to_improve: str
    sentiment: SentimentType
    tags: List[str]
    created_at: datetime
    updated_at: datetime
    acknowledged: bool

class FeedbackStats(BaseModel):
    total: int
    positive: int
    neutral: int
    negative: int

# Security
security = HTTPBearer()

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Initialize demo data
def init_demo_data(db: Session):
    # Check if demo users already exist
    if db.query(User).first():
        return
    
    # Create demo users
    manager = User(
        id=str(uuid.uuid4()),
        name="John Manager",
        email="manager@company.com",
        password_hash=get_password_hash("manager123"),
        role=UserRole.manager,
        team_id="team1"
    )
    
    employee = User(
        id=str(uuid.uuid4()),
        name="Jane Employee",
        email="employee@company.com",
        password_hash=get_password_hash("employee123"),
        role=UserRole.employee,
        team_id="team1"
    )
    
    db.add(manager)
    db.add(employee)
    db.commit()
    
    # Create demo feedback
    demo_feedback = Feedback(
        id=str(uuid.uuid4()),
        manager_id=manager.id,
        employee_id=employee.id,
        strengths="Excellent communication skills and strong problem-solving abilities. Always delivers high-quality work on time.",
        areas_to_improve="Could benefit from taking more leadership initiatives and mentoring junior team members.",
        sentiment=SentimentType.positive,
        tags=["communication", "problem-solving", "reliability"],
        created_at=datetime.utcnow() - timedelta(days=5)
    )
    
    db.add(demo_feedback)
    db.commit()

# Initialize demo data on startup
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        init_demo_data(db)
    finally:
        db.close()

# API Endpoints
@app.post("/auth/login")
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            team_id=user.team_id
        )
    }

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        role=current_user.role,
        team_id=current_user.team_id
    )

@app.get("/users/team-members", response_model=List[UserResponse])
def get_team_members(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.manager:
        raise HTTPException(status_code=403, detail="Only managers can view team members")
    
    team_members = db.query(User).filter(
        User.team_id == current_user.team_id,
        User.role == UserRole.employee
    ).all()
    
    return [UserResponse(
        id=member.id,
        name=member.name,
        email=member.email,
        role=member.role,
        team_id=member.team_id
    ) for member in team_members]

@app.post("/feedback", response_model=FeedbackResponse)
def create_feedback(
    feedback_data: FeedbackCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.manager:
        raise HTTPException(status_code=403, detail="Only managers can create feedback")
    
    # Verify employee exists and is in the same team
    employee = db.query(User).filter(User.id == feedback_data.employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    if employee.team_id != current_user.team_id:
        raise HTTPException(status_code=403, detail="Can only give feedback to team members")
    
    feedback_obj = Feedback(
        manager_id=current_user.id,
        employee_id=feedback_data.employee_id,
        strengths=feedback_data.strengths,
        areas_to_improve=feedback_data.areas_to_improve,
        sentiment=feedback_data.sentiment,
        tags=feedback_data.tags
    )
    
    db.add(feedback_obj)
    db.commit()
    db.refresh(feedback_obj)
    
    # Check if acknowledged
    acknowledgment = db.query(Acknowledgment).filter(
        Acknowledgment.feedback_id == feedback_obj.id
    ).first()
    
    return FeedbackResponse(
        id=feedback_obj.id,
        manager_id=feedback_obj.manager_id,
        employee_id=feedback_obj.employee_id,
        manager_name=current_user.name,
        employee_name=employee.name,
        strengths=feedback_obj.strengths,
        areas_to_improve=feedback_obj.areas_to_improve,
        sentiment=feedback_obj.sentiment,
        tags=feedback_obj.tags,
        created_at=feedback_obj.created_at,
        updated_at=feedback_obj.updated_at,
        acknowledged=acknowledgment is not None
    )

@app.get("/feedback", response_model=List[FeedbackResponse])
def get_feedback(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == UserRole.manager:
        # Managers see feedback they've given
        feedback_list = db.query(Feedback).filter(Feedback.manager_id == current_user.id).all()
    else:
        # Employees see feedback they've received
        feedback_list = db.query(Feedback).filter(Feedback.employee_id == current_user.id).all()
    
    result = []
    for feedback_obj in feedback_list:
        # Get manager and employee names
        manager = db.query(User).filter(User.id == feedback_obj.manager_id).first()
        employee = db.query(User).filter(User.id == feedback_obj.employee_id).first()
        
        # Check if acknowledged
        acknowledgment = db.query(Acknowledgment).filter(
            Acknowledgment.feedback_id == feedback_obj.id
        ).first()
        
        result.append(FeedbackResponse(
            id=feedback_obj.id,
            manager_id=feedback_obj.manager_id,
            employee_id=feedback_obj.employee_id,
            manager_name=manager.name if manager else "Unknown",
            employee_name=employee.name if employee else "Unknown",
            strengths=feedback_obj.strengths,
            areas_to_improve=feedback_obj.areas_to_improve,
            sentiment=feedback_obj.sentiment,
            tags=feedback_obj.tags,
            created_at=feedback_obj.created_at,
            updated_at=feedback_obj.updated_at,
            acknowledged=acknowledgment is not None
        ))
    
    # Sort by created_at descending
    result.sort(key=lambda x: x.created_at, reverse=True)
    return result

@app.post("/feedback/{feedback_id}/acknowledge")
def acknowledge_feedback(
    feedback_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.employee:
        raise HTTPException(status_code=403, detail="Only employees can acknowledge feedback")
    
    # Verify feedback exists and belongs to the employee
    feedback_obj = db.query(Feedback).filter(
        Feedback.id == feedback_id,
        Feedback.employee_id == current_user.id
    ).first()
    
    if not feedback_obj:
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    # Check if already acknowledged
    existing_ack = db.query(Acknowledgment).filter(
        Acknowledgment.feedback_id == feedback_id,
        Acknowledgment.employee_id == current_user.id
    ).first()
    
    if existing_ack:
        raise HTTPException(status_code=400, detail="Feedback already acknowledged")
    
    acknowledgment = Acknowledgment(
        feedback_id=feedback_id,
        employee_id=current_user.id
    )
    
    db.add(acknowledgment)
    db.commit()
    
    return {"message": "Feedback acknowledged successfully"}

@app.get("/feedback/stats", response_model=FeedbackStats)
def get_feedback_stats(
    employee_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role == UserRole.manager:
        # Managers see stats for their team or specific employee
        query = db.query(Feedback).filter(Feedback.manager_id == current_user.id)
        if employee_id:
            query = query.filter(Feedback.employee_id == employee_id)
    else:
        # Employees see their own stats
        query = db.query(Feedback).filter(Feedback.employee_id == current_user.id)
    
    feedback_list = query.all()
    
    total = len(feedback_list)
    positive = len([f for f in feedback_list if f.sentiment == SentimentType.positive])
    neutral = len([f for f in feedback_list if f.sentiment == SentimentType.neutral])
    negative = len([f for f in feedback_list if f.sentiment == SentimentType.negative])
    
    return FeedbackStats(
        total=total,
        positive=positive,
        neutral=neutral,
        negative=negative
    )

@app.get("/")
def root():
    return {"message": "Feedback System API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
