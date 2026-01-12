from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File, Form, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr, validator
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import hashlib
import shutil
from enum import Enum
import json
import asyncio
from bson import ObjectId
import mimetypes

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"

# Evidence storage
EVIDENCE_DIR = ROOT_DIR / "evidence_storage"
EVIDENCE_DIR.mkdir(exist_ok=True)

# Enums
class UserRole(str, Enum):
    ADMIN = "admin"
    INTAKE = "intake"
    ANALYST = "analyst"
    REPORTER = "reporter"
    VIEWER = "viewer"

class CaseStatus(str, Enum):
    NEW = "new"
    UNDER_ANALYSIS = "under_analysis"
    EVIDENCE_COLLECTED = "evidence_collected"
    REPORT_SUBMITTED = "report_submitted"
    CLOSED = "closed"
    ESCALATED = "escalated"

class ViolationType(str, Enum):
    PRIVACY_VIOLATION = "privacy_violation"
    EXTORTION = "extortion"
    TERRORISM = "terrorism"
    HATE_SPEECH = "hate_speech"
    FRAUD = "fraud"
    IDENTITY_THEFT = "identity_theft"
    CYBER_BULLYING = "cyber_bullying"
    OTHER = "other"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PlatformType(str, Enum):
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    TIKTOK = "tiktok"
    SNAPCHAT = "snapchat"
    LINKEDIN = "linkedin"
    OTHER = "other"

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    role: UserRole
    department: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    is_active: bool = True
    profile_image: Optional[str] = None

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: UserRole = UserRole.VIEWER
    department: Optional[str] = None
    phone: Optional[str] = None

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None
    profile_image: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Evidence(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    file_name: str
    file_hash: str
    file_path: str
    file_type: str
    file_size: int
    description: Optional[str] = None
    tags: List[str] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uploaded_by: str

class Case(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_number: str
    title: str
    description: str
    account_url: Optional[str] = None
    platform: Optional[str] = None
    violation_type: ViolationType
    severity: SeverityLevel
    status: CaseStatus = CaseStatus.NEW
    priority: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None
    created_by: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = []
    related_cases: List[str] = []
    victim_info: Optional[Dict[str, Any]] = None
    suspect_info: Optional[Dict[str, Any]] = None

class CaseCreate(BaseModel):
    title: str
    description: str
    account_url: Optional[str] = None
    platform: Optional[str] = None
    violation_type: ViolationType
    severity: SeverityLevel
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    victim_info: Optional[Dict[str, Any]] = None
    suspect_info: Optional[Dict[str, Any]] = None

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    account_url: Optional[str] = None
    platform: Optional[str] = None
    violation_type: Optional[ViolationType] = None
    severity: Optional[SeverityLevel] = None
    status: Optional[CaseStatus] = None
    priority: Optional[int] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    victim_info: Optional[Dict[str, Any]] = None
    suspect_info: Optional[Dict[str, Any]] = None

class Report(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    title: str
    report_content: str
    summary: Optional[str] = None
    recommendations: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str
    report_type: str = "official"
    attachments: List[str] = []

class Notification(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    message: str
    read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notification_type: str = "info"
    link: Optional[str] = None

class DashboardStats(BaseModel):
    total_cases: int
    new_cases: int
    under_analysis: int
    evidence_collected: int
    closed_cases: int
    escalated_cases: int
    critical_cases: int
    high_priority_cases: int
    medium_priority_cases: int
    low_priority_cases: int
    total_users: int
    active_users: int
    cases_by_violation: Dict[str, int]
    cases_by_status: Dict[str, int]
    monthly_trend: List[Dict[str, Any]]

class AuditLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    action: str
    entity_type: str
    entity_id: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def calculate_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Update last login
        await db.users.update_one(
            {"id": user_id},
            {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}}
        )
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_roles: List[UserRole]):
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in [role.value for role in required_roles]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

def generate_case_number() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_id = str(uuid.uuid4())[:6].upper()
    return f"AJC-{timestamp}-{random_id}"

async def create_notification(
    user_id: str, 
    title: str, 
    message: str, 
    notification_type: str = "info",
    link: Optional[str] = None
):
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type,
        link=link
    )
    doc = notification.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.notifications.insert_one(doc)

async def create_audit_log(
    user_id: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: Dict[str, Any],
    request = None
):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details
    )
    
    if request:
        audit_log.ip_address = request.client.host
        audit_log.user_agent = request.headers.get("user-agent")
    
    doc = audit_log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.audit_logs.insert_one(doc)

# Create the main app
app = FastAPI(
    title="Abu Jamal CyberShield API",
    description="Comprehensive Cyber Crime Case Management System",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

api_router = APIRouter(prefix="/api")

# Auth Routes
@api_router.post("/auth/register", response_model=Dict[str, Any])
async def register(user_data: UserCreate):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user_data.password)
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        department=user_data.department,
        phone=user_data.phone
    )
    
    user_doc = user.model_dump()
    user_doc['created_at'] = user_doc['created_at'].isoformat()
    user_doc['updated_at'] = user_doc['updated_at'].isoformat()
    user_doc['password'] = hashed_password
    
    await db.users.insert_one(user_doc)
    
    await create_notification(
        user_id=user.id,
        title="مرحباً بك في Abu Jamal CyberShield",
        message="تم إنشاء حسابك بنجاح. يمكنك الآن تسجيل الدخول واستخدام النظام.",
        notification_type="success"
    )
    
    return {"message": "User created successfully", "user_id": user.id}

@api_router.post("/auth/login", response_model=Dict[str, Any])
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is inactive")
    
    access_token = create_access_token({"sub": user["id"], "role": user["role"]})
    
    user_response = {
        "id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "department": user.get("department"),
        "phone": user.get("phone"),
        "profile_image": user.get("profile_image")
    }
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_response
    }

@api_router.get("/auth/me", response_model=Dict[str, Any])
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@api_router.post("/auth/refresh")
async def refresh_token(current_user: dict = Depends(get_current_user)):
    access_token = create_access_token({"sub": current_user["id"], "role": current_user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/auth/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: dict = Depends(get_current_user)
):
    user = await db.users.find_one({"id": current_user["id"]})
    if not verify_password(current_password, user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    hashed_password = hash_password(new_password)
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"password": hashed_password, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    await create_notification(
        user_id=current_user["id"],
        title="تم تغيير كلمة المرور",
        message="تم تغيير كلمة مرور حسابك بنجاح.",
        notification_type="success"
    )
    
    return {"message": "Password changed successfully"}

# Case Routes
@api_router.post("/cases", response_model=Case)
async def create_case(
    case_data: CaseCreate,
    current_user: dict = Depends(get_current_user),
    request = None
):
    case = Case(
        case_number=generate_case_number(),
        title=case_data.title,
        description=case_data.description,
        account_url=case_data.account_url,
        platform=case_data.platform,
        violation_type=case_data.violation_type,
        severity=case_data.severity,
        created_by=current_user["id"],
        notes=case_data.notes,
        tags=case_data.tags or [],
        victim_info=case_data.victim_info,
        suspect_info=case_data.suspect_info,
        priority=1 if case_data.severity == SeverityLevel.CRITICAL else 
               2 if case_data.severity == SeverityLevel.HIGH else
               3 if case_data.severity == SeverityLevel.MEDIUM else 4
    )
    
    doc = case.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.cases.insert_one(doc)
    
    await create_notification(
        user_id=current_user["id"],
        title="قضية جديدة",
        message=f"تم إنشاء القضية {case.case_number}: {case.title}",
        notification_type="success",
        link=f"/cases/{case.id}"
    )
    
    await create_audit_log(
        user_id=current_user["id"],
        action="create",
        entity_type="case",
        entity_id=case.id,
        details={"case_number": case.case_number, "title": case.title},
        request=request
    )
    
    # Notify admins and analysts
    admins_analysts = await db.users.find({
        "role": {"$in": ["admin", "analyst"]},
        "id": {"$ne": current_user["id"]}
    }).to_list(None)
    
    for user in admins_analysts:
        await create_notification(
            user_id=user["id"],
            title="قضية جديدة تحتاج المراجعة",
            message=f"تم إنشاء قضية جديدة: {case.case_number}",
            notification_type="info",
            link=f"/cases/{case.id}"
        )
    
    return case

@api_router.get("/cases", response_model=List[Case])
async def get_cases(
    status: Optional[CaseStatus] = None,
    violation_type: Optional[ViolationType] = None,
    severity: Optional[SeverityLevel] = None,
    assigned_to: Optional[str] = None,
    created_by: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    query = {}
    
    if status:
        query["status"] = status.value
    if violation_type:
        query["violation_type"] = violation_type.value
    if severity:
        query["severity"] = severity.value
    if assigned_to:
        query["assigned_to"] = assigned_to
    if created_by:
        query["created_by"] = created_by
    
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"case_number": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    
    skip = (page - 1) * limit
    
    cases_cursor = db.cases.find(query, {"_id": 0})
    total = await db.cases.count_documents(query)
    
    cases = await cases_cursor.sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert datetime strings back to datetime objects
    for case in cases:
        for date_field in ['created_at', 'updated_at', 'closed_at']:
            if case.get(date_field) and isinstance(case[date_field], str):
                case[date_field] = datetime.fromisoformat(case[date_field].replace('Z', '+00:00'))
    
    return {
        "cases": cases,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/cases/{case_id}", response_model=Case)
async def get_case(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # Convert datetime strings
    for date_field in ['created_at', 'updated_at', 'closed_at']:
        if case.get(date_field) and isinstance(case[date_field], str):
            case[date_field] = datetime.fromisoformat(case[date_field].replace('Z', '+00:00'))
    
    return case

@api_router.patch("/cases/{case_id}", response_model=Case)
async def update_case(
    case_id: str,
    case_update: CaseUpdate,
    current_user: dict = Depends(get_current_user),
    request = None
):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    update_data = {k: v for k, v in case_update.model_dump(exclude_unset=True).items() if v is not None}
    
    if update_data:
        update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Update priority if severity changed
        if "severity" in update_data:
            severity = update_data["severity"]
            update_data["priority"] = (
                1 if severity == SeverityLevel.CRITICAL else
                2 if severity == SeverityLevel.HIGH else
                3 if severity == SeverityLevel.MEDIUM else 4
            )
        
        # If case is being closed, add closed_at timestamp
        if "status" in update_data and update_data["status"] == CaseStatus.CLOSED:
            update_data["closed_at"] = datetime.now(timezone.utc).isoformat()
        
        await db.cases.update_one({"id": case_id}, {"$set": update_data})
        
        await create_audit_log(
            user_id=current_user["id"],
            action="update",
            entity_type="case",
            entity_id=case_id,
            details={"updates": update_data},
            request=request
        )
        
        # Send notifications for important updates
        if "status" in update_data:
            await create_notification(
                user_id=case["created_by"],
                title="تحديث حالة القضية",
                message=f"تم تحديث حالة القضية {case['case_number']} إلى {update_data['status']}",
                notification_type="info",
                link=f"/cases/{case_id}"
            )
        
        if "assigned_to" in update_data and update_data["assigned_to"]:
            await create_notification(
                user_id=update_data["assigned_to"],
                title="تم تعيين قضية لك",
                message=f"تم تعيين القضية {case['case_number']} لك",
                notification_type="info",
                link=f"/cases/{case_id}"
            )
    
    updated_case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    
    # Convert datetime strings
    for date_field in ['created_at', 'updated_at', 'closed_at']:
        if updated_case.get(date_field) and isinstance(updated_case[date_field], str):
            updated_case[date_field] = datetime.fromisoformat(updated_case[date_field].replace('Z', '+00:00'))
    
    return updated_case

@api_router.delete("/cases/{case_id}")
async def delete_case(
    case_id: str,
    current_user: dict = Depends(require_role([UserRole.ADMIN])),
    request = None
):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    result = await db.cases.delete_one({"id": case_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # Delete related evidence files
    evidence_list = await db.evidence.find({"case_id": case_id}).to_list(None)
    for evidence in evidence_list:
        try:
            file_path = Path(evidence["file_path"])
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            logging.error(f"Failed to delete evidence file: {e}")
    
    await db.evidence.delete_many({"case_id": case_id})
    await db.reports.delete_many({"case_id": case_id})
    
    await create_audit_log(
        user_id=current_user["id"],
        action="delete",
        entity_type="case",
        entity_id=case_id,
        details={"case_number": case["case_number"], "title": case["title"]},
        request=request
    )
    
    return {"message": "Case deleted successfully"}

# Evidence Routes
@api_router.post("/cases/{case_id}/evidence", response_model=Dict[str, Any])
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user),
    request = None
):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # Check file size (max 50MB)
    file_content = await file.read()
    file_size = len(file_content)
    
    if file_size > 50 * 1024 * 1024:  # 50MB
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")
    
    file_hash = calculate_file_hash(file_content)
    
    # Check for duplicate files
    existing_evidence = await db.evidence.find_one({"file_hash": file_hash, "case_id": case_id})
    if existing_evidence:
        raise HTTPException(status_code=400, detail="Duplicate file detected")
    
    file_extension = Path(file.filename).suffix.lower() if '.' in file.filename else ''
    safe_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = EVIDENCE_DIR / case_id
    file_path.mkdir(exist_ok=True, parents=True)
    
    full_path = file_path / safe_filename
    with open(full_path, "wb") as f:
        f.write(file_content)
    
    evidence_tags = tags.split(",") if tags else []
    
    evidence = Evidence(
        case_id=case_id,
        file_name=file.filename,
        file_hash=file_hash,
        file_path=str(full_path),
        file_type=file.content_type or mimetypes.guess_type(file.filename)[0] or "application/octet-stream",
        file_size=file_size,
        description=description,
        tags=evidence_tags,
        uploaded_by=current_user["id"]
    )
    
    doc = evidence.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.evidence.insert_one(doc)
    
    # Update case status if it's new
    if case["status"] == CaseStatus.NEW:
        await db.cases.update_one(
            {"id": case_id},
            {"$set": {"status": CaseStatus.UNDER_ANALYSIS.value, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
    
    await create_notification(
        user_id=case["created_by"],
        title="تم رفع دليل جديد",
        message=f"تم رفع دليل جديد للقضية {case['case_number']}",
        notification_type="info",
        link=f"/cases/{case_id}"
    )
    
    await create_audit_log(
        user_id=current_user["id"],
        action="upload",
        entity_type="evidence",
        entity_id=evidence.id,
        details={"case_id": case_id, "file_name": file.filename, "file_size": file_size},
        request=request
    )
    
    return {
        "message": "Evidence uploaded successfully",
        "evidence_id": evidence.id,
        "file_hash": file_hash,
        "file_size": file_size
    }

@api_router.get("/cases/{case_id}/evidence", response_model=List[Evidence])
async def get_case_evidence(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    evidence_list = await db.evidence.find({"case_id": case_id}, {"_id": 0}).sort("timestamp", -1).to_list(None)
    
    for evidence in evidence_list:
        if isinstance(evidence['timestamp'], str):
            evidence['timestamp'] = datetime.fromisoformat(evidence['timestamp'].replace('Z', '+00:00'))
    
    return evidence_list

@api_router.delete("/cases/{case_id}/evidence/{evidence_id}")
async def delete_evidence(
    case_id: str,
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    request = None
):
    evidence = await db.evidence.find_one({"id": evidence_id, "case_id": case_id})
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Delete file
    try:
        file_path = Path(evidence["file_path"])
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        logging.error(f"Failed to delete evidence file: {e}")
    
    await db.evidence.delete_one({"id": evidence_id})
    
    await create_audit_log(
        user_id=current_user["id"],
        action="delete",
        entity_type="evidence",
        entity_id=evidence_id,
        details={"file_name": evidence["file_name"]},
        request=request
    )
    
    return {"message": "Evidence deleted successfully"}

@api_router.get("/evidence/{evidence_id}/download")
async def download_evidence(
    evidence_id: str,
    current_user: dict = Depends(get_current_user)
):
    evidence = await db.evidence.find_one({"id": evidence_id})
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    file_path = Path(evidence["file_path"])
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=file_path,
        filename=evidence["file_name"],
        media_type=evidence["file_type"]
    )

# Report Routes
@api_router.post("/cases/{case_id}/report", response_model=Dict[str, Any])
async def generate_report(
    case_id: str,
    title: Optional[str] = "تقرير رسمي",
    summary: Optional[str] = None,
    recommendations: Optional[str] = None,
    report_type: str = "official",
    current_user: dict = Depends(get_current_user),
    request = None
):
    case = await db.cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    evidence_list = await db.evidence.find({"case_id": case_id}, {"_id": 0}).to_list(None)
    
    # Get assigned user info if exists
    assigned_user = None
    if case.get("assigned_to"):
        assigned_user = await db.users.find_one({"id": case["assigned_to"]}, {"_id": 0, "password": 0})
    
    # Get creator info
    creator = await db.users.find_one({"id": case["created_by"]}, {"_id": 0, "password": 0})
    
    report_content = f"""=== Abu Jamal CyberShield - Official Report ===

Case Number: {case['case_number']}
Title: {case['title']}
Status: {case['status']}
Severity: {case['severity']}
Violation Type: {case['violation_type']}
Priority: {case.get('priority', 'N/A')}

Description:
{case['description']}

Case Information:
Platform: {case.get('platform', 'N/A')}
Account URL: {case.get('account_url', 'N/A')}
Created: {case['created_at']}
Last Updated: {case['updated_at']}

Personnel:
Case Creator: {creator.get('full_name', 'N/A')} ({creator.get('email', 'N/A')})
Assigned To: {assigned_user.get('full_name', 'N/A') if assigned_user else 'Not Assigned'}

Evidence Summary:
Total Evidence Files: {len(evidence_list)}
Total Evidence Size: {sum(e.get('file_size', 0) for e in evidence_list) / (1024*1024):.2f} MB

Evidence Details:
"""
    
    for idx, evidence in enumerate(evidence_list, 1):
        timestamp = evidence.get('timestamp', 'N/A')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime("%Y-%m-%d %H:%M:%S")
        
        report_content += f"""
{idx}. File: {evidence['file_name']}
   Type: {evidence['file_type']}
   Size: {evidence.get('file_size', 0) / 1024:.2f} KB
   Hash (SHA256): {evidence['file_hash']}
   Uploaded: {timestamp}
   Description: {evidence.get('description', 'N/A')}
   Tags: {', '.join(evidence.get('tags', [])) if evidence.get('tags') else 'N/A'}
"""
    
    if case.get('victim_info'):
        report_content += f"""

Victim Information:
{json.dumps(case['victim_info'], indent=2, ensure_ascii=False)}
"""
    
    if case.get('suspect_info'):
        report_content += f"""

Suspect Information:
{json.dumps(case['suspect_info'], indent=2, ensure_ascii=False)}
"""
    
    report_content += f"""

Notes:
{case.get('notes', 'N/A')}

{summary if summary else 'Summary: N/A'}

{recommendations if recommendations else 'Recommendations: N/A'}

Generated By: {current_user['full_name']} ({current_user['email']})
Generated At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

=== End of Report ===
"""
    
    report = Report(
        case_id=case_id,
        title=title,
        report_content=report_content,
        summary=summary,
        recommendations=recommendations,
        generated_by=current_user["id"],
        report_type=report_type
    )
    
    doc = report.model_dump()
    doc['generated_at'] = doc['generated_at'].isoformat()
    
    await db.reports.insert_one(doc)
    
    # Update case status
    await db.cases.update_one(
        {"id": case_id},
        {"$set": {"status": CaseStatus.REPORT_SUBMITTED.value, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    await create_notification(
        user_id=case["created_by"],
        title="تم إنشاء التقرير",
        message=f"تم إنشاء التقرير للقضية {case['case_number']}",
        notification_type="success",
        link=f"/cases/{case_id}"
    )
    
    await create_audit_log(
        user_id=current_user["id"],
        action="generate",
        entity_type="report",
        entity_id=report.id,
        details={"case_id": case_id, "title": title},
        request=request
    )
    
    return {
        "message": "Report generated successfully",
        "report_id": report.id,
        "title": title,
        "generated_at": report.generated_at
    }

@api_router.get("/cases/{case_id}/reports", response_model=List[Report])
async def get_case_reports(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    reports = await db.reports.find({"case_id": case_id}, {"_id": 0}).sort("generated_at", -1).to_list(None)
    
    for report in reports:
        if isinstance(report['generated_at'], str):
            report['generated_at'] = datetime.fromisoformat(report['generated_at'].replace('Z', '+00:00'))
    
    return reports

@api_router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    report = await db.reports.find_one({"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Create a temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write(report["report_content"])
        temp_path = f.name
    
    return FileResponse(
        path=temp_path,
        filename=f"report-{report_id}.txt",
        media_type="text/plain"
    )

# Dashboard Routes
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    # Case statistics
    total_cases = await db.cases.count_documents({})
    new_cases = await db.cases.count_documents({"status": CaseStatus.NEW.value})
    under_analysis = await db.cases.count_documents({"status": CaseStatus.UNDER_ANALYSIS.value})
    evidence_collected = await db.cases.count_documents({"status": CaseStatus.EVIDENCE_COLLECTED.value})
    closed_cases = await db.cases.count_documents({"status": CaseStatus.CLOSED.value})
    escalated_cases = await db.cases.count_documents({"status": CaseStatus.ESCALATED.value})
    
    # Priority statistics
    critical_cases = await db.cases.count_documents({"severity": SeverityLevel.CRITICAL.value})
    high_priority_cases = await db.cases.count_documents({"severity": SeverityLevel.HIGH.value})
    medium_priority_cases = await db.cases.count_documents({"severity": SeverityLevel.MEDIUM.value})
    low_priority_cases = await db.cases.count_documents({"severity": SeverityLevel.LOW.value})
    
    # User statistics
    total_users = await db.users.count_documents({})
    active_users = await db.users.count_documents({"is_active": True})
    
    # Cases by violation type
    cases_by_violation = {}
    for violation in ViolationType:
        count = await db.cases.count_documents({"violation_type": violation.value})
        cases_by_violation[violation.value] = count
    
    # Cases by status
    cases_by_status = {}
    for status in CaseStatus:
        count = await db.cases.count_documents({"status": status.value})
        cases_by_status[status.value] = count
    
    # Monthly trend (last 6 months)
    monthly_trend = []
    for i in range(6):
        month_start = datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=30*i)
        month_end = month_start + timedelta(days=30)
        
        month_cases = await db.cases.count_documents({
            "created_at": {
                "$gte": month_start.isoformat(),
                "$lt": month_end.isoformat()
            }
        })
        
        monthly_trend.append({
            "month": month_start.strftime("%Y-%m"),
            "cases": month_cases
        })
    
    monthly_trend.reverse()  # Sort from oldest to newest
    
    return DashboardStats(
        total_cases=total_cases,
        new_cases=new_cases,
        under_analysis=under_analysis,
        evidence_collected=evidence_collected,
        closed_cases=closed_cases,
        escalated_cases=escalated_cases,
        critical_cases=critical_cases,
        high_priority_cases=high_priority_cases,
        medium_priority_cases=medium_priority_cases,
        low_priority_cases=low_priority_cases,
        total_users=total_users,
        active_users=active_users,
        cases_by_violation=cases_by_violation,
        cases_by_status=cases_by_status,
        monthly_trend=monthly_trend
    )

@api_router.get("/dashboard/activity")
async def get_recent_activity(
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    # Get recent cases
    recent_cases = await db.cases.find(
        {},
        {"_id": 0, "id": 1, "case_number": 1, "title": 1, "status": 1, "created_at": 1, "severity": 1}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    # Get recent evidence
    recent_evidence = await db.evidence.find(
        {},
        {"_id": 0, "id": 1, "case_id": 1, "file_name": 1, "timestamp": 1, "uploaded_by": 1}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    # Get recent reports
    recent_reports = await db.reports.find(
        {},
        {"_id": 0, "id": 1, "case_id": 1, "title": 1, "generated_at": 1, "generated_by": 1}
    ).sort("generated_at", -1).limit(limit).to_list(limit)
    
    # Convert datetime strings
    for case in recent_cases:
        if case.get('created_at') and isinstance(case['created_at'], str):
            case['created_at'] = datetime.fromisoformat(case['created_at'].replace('Z', '+00:00'))
    
    for evidence in recent_evidence:
        if evidence.get('timestamp') and isinstance(evidence['timestamp'], str):
            evidence['timestamp'] = datetime.fromisoformat(evidence['timestamp'].replace('Z', '+00:00'))
    
    for report in recent_reports:
        if report.get('generated_at') and isinstance(report['generated_at'], str):
            report['generated_at'] = datetime.fromisoformat(report['generated_at'].replace('Z', '+00:00'))
    
    return {
        "recent_cases": recent_cases,
        "recent_evidence": recent_evidence,
        "recent_reports": recent_reports
    }

# User Management Routes
@api_router.get("/users", response_model=List[User])
async def get_users(
    current_user: dict = Depends(require_role([UserRole.ADMIN])),
    page: int = 1,
    limit: int = 20,
    role: Optional[UserRole] = None,
    active: Optional[bool] = None
):
    query = {}
    
    if role:
        query["role"] = role.value
    if active is not None:
        query["is_active"] = active
    
    skip = (page - 1) * limit
    
    users_cursor = db.users.find(query, {"_id": 0, "password": 0})
    total = await db.users.count_documents(query)
    
    users = await users_cursor.sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert datetime strings
    for user in users:
        for date_field in ['created_at', 'updated_at', 'last_login']:
            if user.get(date_field) and isinstance(user[date_field], str):
                user[date_field] = datetime.fromisoformat(user[date_field].replace('Z', '+00:00'))
    
    return {
        "users": users,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

@api_router.post("/users", response_model=Dict[str, Any])
async def create_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_role([UserRole.ADMIN])),
    request = None
):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user_data.password)
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        department=user_data.department,
        phone=user_data.phone
    )
    
    user_doc = user.model_dump()
    user_doc['created_at'] = user_doc['created_at'].isoformat()
    user_doc['updated_at'] = user_doc['updated_at'].isoformat()
    user_doc['password'] = hashed_password
    
    await db.users.insert_one(user_doc)
    
    await create_notification(
        user_id=user.id,
        title="مرحباً بك في Abu Jamal CyberShield",
        message=f"تم إنشاء حسابك بنجاح. يمكنك الآن تسجيل الدخول واستخدام النظام. دورك: {user_data.role}",
        notification_type="success"
    )
    
    await create_audit_log(
        user_id=current_user["id"],
        action="create",
        entity_type="user",
        entity_id=user.id,
        details={"email": user.email, "role": user.role},
        request=request
    )
    
    return {
        "message": "User created successfully",
        "user_id": user.id,
        "email": user.email,
        "role": user.role
    }

@api_router.patch("/users/{user_id}", response_model=Dict[str, Any])
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: dict = Depends(require_role([UserRole.ADMIN])),
    request = None
):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = {k: v for k, v in user_update.model_dump(exclude_unset=True).items() if v is not None}
    
    if update_data:
        update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        await db.users.update_one({"id": user_id}, {"$set": update_data})
        
        await create_audit_log(
            user_id=current_user["id"],
            action="update",
            entity_type="user",
            entity_id=user_id,
            details={"updates": update_data},
            request=request
        )
        
        # Send notification to user if their role or status changed
        if "role" in update_data or "is_active" in update_data:
            message = "تم تحديث معلومات حسابك"
            if "role" in update_data:
                message += f". دورك الجديد: {update_data['role']}"
            if "is_active" in update_data:
                status = "مفعل" if update_data["is_active"] else "موقوف"
                message += f". حالة حسابك: {status}"
            
            await create_notification(
                user_id=user_id,
                title="تم تحديث حسابك",
                message=message,
                notification_type="info"
            )
    
    return {"message": "User updated successfully"}

@api_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_role([UserRole.ADMIN])),
    request = None
):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if user has created any cases
    user_cases = await db.cases.count_documents({"created_by": user_id})
    if user_cases > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete user with {user_cases} associated cases. Reassign cases first."
        )
    
    await db.users.delete_one({"id": user_id})
    
    await create_audit_log(
        user_id=current_user["id"],
        action="delete",
        entity_type="user",
        entity_id=user_id,
        details={"email": user["email"], "full_name": user.get("full_name")},
        request=request
    )
    
    return {"message": "User deleted successfully"}

@api_router.get("/users/stats")
async def get_user_stats(current_user: dict = Depends(require_role([UserRole.ADMIN]))):
    # Count users by role
    roles = [role.value for role in UserRole]
    role_counts = {}
    
    for role in roles:
        count = await db.users.count_documents({"role": role})
        role_counts[role] = count
    
    # Count active vs inactive users
    active_users = await db.users.count_documents({"is_active": True})
    inactive_users = await db.users.count_documents({"is_active": False})
    
    # Get users with most cases
    pipeline = [
        {"$group": {"_id": "$created_by", "case_count": {"$sum": 1}}},
        {"$sort": {"case_count": -1}},
        {"$limit": 10}
    ]
    
    top_users = await db.cases.aggregate(pipeline).to_list(10)
    
    # Get user details for top users
    user_details = []
    for user_stat in top_users:
        user = await db.users.find_one({"id": user_stat["_id"]}, {"_id": 0, "password": 0})
        if user:
            user_details.append({
                **user,
                "case_count": user_stat["case_count"]
            })
    
    return {
        "role_distribution": role_counts,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "top_users": user_details
    }

# Notification Routes
@api_router.get("/notifications", response_model=List[Notification])
async def get_notifications(
    unread_only: bool = False,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    query = {"user_id": current_user["id"]}
    
    if unread_only:
        query["read"] = False
    
    notifications = await db.notifications.find(
        query,
        {"_id": 0}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    for notification in notifications:
        if isinstance(notification['created_at'], str):
            notification['created_at'] = datetime.fromisoformat(notification['created_at'].replace('Z', '+00:00'))
    
    return notifications

@api_router.patch("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    result = await db.notifications.update_one(
        {"id": notification_id, "user_id": current_user["id"]},
        {"$set": {"read": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    return {"message": "Notification marked as read"}

@api_router.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    result = await db.notifications.delete_one(
        {"id": notification_id, "user_id": current_user["id"]}
    )
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    return {"message": "Notification deleted"}

@api_router.post("/notifications/mark-all-read")
async def mark_all_notifications_read(current_user: dict = Depends(get_current_user)):
    await db.notifications.update_many(
        {"user_id": current_user["id"], "read": False},
        {"$set": {"read": True}}
    )
    
    return {"message": "All notifications marked as read"}

# Audit Log Routes (Admin only)
@api_router.get("/audit-logs")
async def get_audit_logs(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    user_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_role([UserRole.ADMIN]))
):
    query = {}
    
    if entity_type:
        query["entity_type"] = entity_type
    if entity_id:
        query["entity_id"] = entity_id
    if user_id:
        query["user_id"] = user_id
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query.setdefault("timestamp", {})["$gte"] = start_dt.isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start date format")
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query.setdefault("timestamp", {})["$lte"] = end_dt.isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end date format")
    
    skip = (page - 1) * limit
    
    logs_cursor = db.audit_logs.find(query, {"_id": 0})
    total = await db.audit_logs.count_documents(query)
    
    logs = await logs_cursor.sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert datetime strings and enrich with user info
    for log in logs:
        if isinstance(log['timestamp'], str):
            log['timestamp'] = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
        
        # Get user info
        user = await db.users.find_one({"id": log["user_id"]}, {"_id": 0, "full_name": 1, "email": 1})
        if user:
            log["user_info"] = user
    
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

# Include router
app.include_router(api_router)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "https://cybercrime-unit.preview.emergentagent.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        # Check MongoDB connection
        await client.admin.command('ping')
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

@app.get("/")
async def root():
    return {
        "message": "Welcome to Abu Jamal CyberShield API",
        "version": "2.0.0",
        "docs": "/api/docs",
        "health": "/health"
    }

# Startup event
@app.on_event("startup")
async def startup_db_client():
    try:
        await client.admin.command('ping')
        logger.info("Successfully connected to MongoDB")
        
        # Create indexes
        await db.cases.create_index([("case_number", 1)], unique=True)
        await db.cases.create_index([("status", 1)])
        await db.cases.create_index([("severity", 1)])
        await db.cases.create_index([("created_at", -1)])
        await db.users.create_index([("email", 1)], unique=True)
        await db.evidence.create_index([("case_id", 1)])
        await db.evidence.create_index([("file_hash", 1)])
        await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
        await db.audit_logs.create_index([("timestamp", -1)])
        
        logger.info("Database indexes created")
        
        # Create default admin user if not exists
        admin_exists = await db.users.find_one({"email": "admin@test.com"})
        if not admin_exists:
            import hashlib
            import uuid
            from datetime import datetime, timezone
            
            admin_user = {
                "id": str(uuid.uuid4()),
                "email": "admin@test.com",
                "full_name": "Abu Jamal",
                "role": "admin",
                "department": "Administration",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True,
                "password": pwd_context.hash("admin123")
            }
            await db.users.insert_one(admin_user)
            logger.info("Default admin user created")
        
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise

# Shutdown event
@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    logger.info("MongoDB connection closed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)