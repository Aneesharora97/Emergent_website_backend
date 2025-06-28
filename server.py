from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import hashlib
import jwt
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security
security = HTTPBearer()

# Define Models
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

class ContactMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: str
    subject: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ContactMessageCreate(BaseModel):
    name: str
    email: str
    subject: str
    message: str

class PublicationStats(BaseModel):
    total_publications: int = 0
    total_citations: int = 0
    h_index: int = 0
    recent_publications: int = 0

class BlogPost(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    slug: str
    content: str
    excerpt: str
    category: str  # "academic", "thoughts", "research"
    tags: List[str] = []
    featured_image: Optional[str] = None
    published: bool = False
    author: str = "Dr. [Your Name]"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    views: int = 0

class BlogPostCreate(BaseModel):
    title: str
    slug: str
    content: str
    excerpt: str
    category: str
    tags: List[str] = []
    featured_image: Optional[str] = None
    published: bool = False

class BlogPostUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    content: Optional[str] = None
    excerpt: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    featured_image: Optional[str] = None
    published: Optional[bool] = None

class AnalyticsEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # page_view, click, download, etc.
    page_url: str
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    referrer: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = {}

class AnalyticsEventCreate(BaseModel):
    event_type: str
    page_url: str
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    referrer: Optional[str] = None
    session_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = {}

class SiteSettings(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    site_title: str = "Dr. [Your Name] - Economics PhD"
    site_description: str = "Personal academic portfolio and research blog"
    contact_email: str = "[your.email@university.edu]"
    linkedin_url: str = ""
    google_scholar_url: str = ""
    orcid_id: str = ""
    university: str = "[University Name]"
    department: str = "[Department Name]"
    research_interests: List[str] = []
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class SiteSettingsUpdate(BaseModel):
    site_title: Optional[str] = None
    site_description: Optional[str] = None
    contact_email: Optional[str] = None
    linkedin_url: Optional[str] = None
    google_scholar_url: Optional[str] = None
    orcid_id: Optional[str] = None
    university: Optional[str] = None
    department: Optional[str] = None
    research_interests: Optional[List[str]] = None

class AdminLogin(BaseModel):
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Utility functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Routes
@api_router.get("/")
async def root():
    return {"message": "Economics PhD Portfolio API with CMS"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

@api_router.post("/contact", response_model=ContactMessage)
async def create_contact_message(contact_data: ContactMessageCreate):
    try:
        contact_dict = contact_data.dict()
        contact_obj = ContactMessage(**contact_dict)
        
        # Save to database
        await db.contact_messages.insert_one(contact_obj.dict())
        
        return contact_obj
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/contact", response_model=List[ContactMessage])
async def get_contact_messages():
    try:
        messages = await db.contact_messages.find().sort("timestamp", -1).to_list(1000)
        return [ContactMessage(**message) for message in messages]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/publications/stats", response_model=PublicationStats)
async def get_publication_stats():
    return PublicationStats(
        total_publications=15,
        total_citations=342,
        h_index=8,
        recent_publications=5
    )

# Blog Routes
@api_router.get("/blog", response_model=List[BlogPost])
async def get_blog_posts(category: Optional[str] = None, published: bool = True, limit: int = 10, skip: int = 0):
    try:
        query = {"published": published} if published else {}
        if category:
            query["category"] = category
            
        posts = await db.blog_posts.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        return [BlogPost(**post) for post in posts]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/blog/{slug}", response_model=BlogPost)
async def get_blog_post(slug: str):
    try:
        post = await db.blog_posts.find_one({"slug": slug})
        if not post:
            raise HTTPException(status_code=404, detail="Blog post not found")
        
        # Increment view count
        await db.blog_posts.update_one({"slug": slug}, {"$inc": {"views": 1}})
        post["views"] = post.get("views", 0) + 1
        
        return BlogPost(**post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/blog", response_model=BlogPost)
async def create_blog_post(post_data: BlogPostCreate, token: dict = Depends(verify_token)):
    try:
        # Check if slug already exists
        existing = await db.blog_posts.find_one({"slug": post_data.slug})
        if existing:
            raise HTTPException(status_code=400, detail="Blog post with this slug already exists")
        
        post_dict = post_data.dict()
        post_obj = BlogPost(**post_dict)
        
        await db.blog_posts.insert_one(post_obj.dict())
        return post_obj
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.put("/blog/{slug}", response_model=BlogPost)
async def update_blog_post(slug: str, post_data: BlogPostUpdate, token: dict = Depends(verify_token)):
    try:
        existing_post = await db.blog_posts.find_one({"slug": slug})
        if not existing_post:
            raise HTTPException(status_code=404, detail="Blog post not found")
        
        update_data = {k: v for k, v in post_data.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        await db.blog_posts.update_one({"slug": slug}, {"$set": update_data})
        
        updated_post = await db.blog_posts.find_one({"slug": slug})
        return BlogPost(**updated_post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.delete("/blog/{slug}")
async def delete_blog_post(slug: str, token: dict = Depends(verify_token)):
    try:
        result = await db.blog_posts.delete_one({"slug": slug})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Blog post not found")
        return {"message": "Blog post deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Analytics Routes
@api_router.post("/analytics/event")
async def track_analytics_event(event_data: AnalyticsEventCreate):
    try:
        event_dict = event_data.dict()
        event_obj = AnalyticsEvent(**event_dict)
        
        await db.analytics_events.insert_one(event_obj.dict())
        return {"message": "Event tracked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/analytics/stats")
async def get_analytics_stats(token: dict = Depends(verify_token)):
    try:
        # Get stats for the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Page views
        page_views = await db.analytics_events.count_documents({
            "event_type": "page_view",
            "timestamp": {"$gte": thirty_days_ago}
        })
        
        # Unique visitors (by session_id)
        unique_visitors_pipeline = [
            {"$match": {"event_type": "page_view", "timestamp": {"$gte": thirty_days_ago}}},
            {"$group": {"_id": "$session_id"}},
            {"$count": "unique_visitors"}
        ]
        unique_visitors_result = await db.analytics_events.aggregate(unique_visitors_pipeline).to_list(1)
        unique_visitors = unique_visitors_result[0]["unique_visitors"] if unique_visitors_result else 0
        
        # Top pages
        top_pages_pipeline = [
            {"$match": {"event_type": "page_view", "timestamp": {"$gte": thirty_days_ago}}},
            {"$group": {"_id": "$page_url", "views": {"$sum": 1}}},
            {"$sort": {"views": -1}},
            {"$limit": 10}
        ]
        top_pages = await db.analytics_events.aggregate(top_pages_pipeline).to_list(10)
        
        return {
            "page_views": page_views,
            "unique_visitors": unique_visitors,
            "top_pages": top_pages,
            "period": "last_30_days"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Site Settings Routes
@api_router.get("/settings", response_model=SiteSettings)
async def get_site_settings():
    try:
        settings = await db.site_settings.find_one()
        if not settings:
            # Create default settings
            default_settings = SiteSettings()
            await db.site_settings.insert_one(default_settings.dict())
            return default_settings
        return SiteSettings(**settings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.put("/settings", response_model=SiteSettings)
async def update_site_settings(settings_data: SiteSettingsUpdate, token: dict = Depends(verify_token)):
    try:
        update_data = {k: v for k, v in settings_data.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        await db.site_settings.update_one({}, {"$set": update_data}, upsert=True)
        
        updated_settings = await db.site_settings.find_one()
        return SiteSettings(**updated_settings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Admin Authentication
@api_router.post("/auth/login", response_model=Token)
async def admin_login(login_data: AdminLogin):
    # Simple password authentication (in production, use proper user management)
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")  # Change this!
    
    if login_data.password != admin_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": "admin"}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.get("/auth/verify")
async def verify_admin_token(token: dict = Depends(verify_token)):
    return {"message": "Token is valid", "user": token.get("sub")}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()