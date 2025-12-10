# main.py
import os
import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ---------------------
# Config
# ---------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "artifacts")
DB_PATH = os.path.join(BASE_DIR, "lumina.db")
SECRET_KEY = os.environ.get("LUMINA_SECRET_KEY", "lumina_secret_key_change_this_in_production")

DATABASE_URL = f"sqlite:///{DB_PATH}"

# ---------------------
# Database (SQLAlchemy sync)
# ---------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------
# Global product caches (same as your Flask code)
# ---------------------
PRODUCTS_MAP: Dict[str, Dict[str, Any]] = {}
PRODUCT_NAMES_MAP: Dict[str, str] = {}
RECOMMENDATIONS: Dict[str, List[Dict[str, Any]]] = {}


def load_data():
    global PRODUCTS_MAP, PRODUCT_NAMES_MAP, RECOMMENDATIONS
    PRODUCTS_MAP = {}
    PRODUCT_NAMES_MAP = {}
    RECOMMENDATIONS = {}

    if not os.path.exists(DATA_DIR):
        print(f"❌ DATA_DIR not found: {DATA_DIR}")
        return

    possible_filenames = ["product_matrix.json", "product_index_map.json"]
    matrix_path = None
    for fname in possible_filenames:
        temp = os.path.join(DATA_DIR, fname)
        if os.path.exists(temp):
            matrix_path = temp
            break

    if matrix_path:
        try:
            with open(matrix_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            data_list = raw if isinstance(raw, list) else [v for k, v in raw.items()] if isinstance(raw, dict) else []

            for item in data_list:
                if isinstance(item, str):
                    continue
                pid = str(item.get("product_id_numeric", item.get("product_id", "N/A")))
                if pid != "None":
                    PRODUCTS_MAP[pid] = item
                    PRODUCT_NAMES_MAP[item.get("product_name", "").strip()] = pid
            print(f"✅ Data Loaded: {len(PRODUCTS_MAP)} products.")
        except Exception as e:
            print(f"❌ Error loading data: {e}")

    rec_path = os.path.join(DATA_DIR, "precomputed_hybrid.json")
    if os.path.exists(rec_path):
        try:
            with open(rec_path, "r", encoding="utf-8") as f:
                RECOMMENDATIONS = json.load(f)
        except Exception:
            pass


def normalize_product(p: Dict[str, Any]) -> Dict[str, Any]:
    try:
        price = float(p.get("actual_price", 0))
    except Exception:
        price = 0.0
    try:
        disc = float(p.get("discounted_price", price))
    except Exception:
        disc = price
    return {
        "p_id": str(p.get("product_id_numeric")),
        "name": p.get("product_name", "Unknown"),
        "brand": p.get("Brand", "Generic"),
        "rating": p.get("rating", 0),
        "prices": price,
        "discounted_price": disc,
        "img_link": p.get("img_link", ""),
        "p_link": p.get("product_link", "#"),
    }


# ---------------------
# FastAPI app + templates + sessions
# ---------------------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="lumina_session")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Optionally serve static files if you have them (like in Flask's static folder)
static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ---------------------
# Startup event: create tables & load data
# ---------------------
@app.on_event("startup")
def on_startup():
    # create DB + tables
    Base.metadata.create_all(bind=engine)
    # load product/recommendation data
    load_data()


# ---------------------
# Pydantic models for API inputs
# ---------------------
class SignupIn(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


# ---------------------
# Routes
# ---------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user_name = None
    user_id = request.session.get("user_id")
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user_name = user.name
    return templates.TemplateResponse("index.html", {"request": request, "user_name": user_name})


# --- AUTH ROUTES ---
@app.post("/api/signup")
def signup(payload: SignupIn, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        return JSONResponse({"status": "error", "message": "Email already registered"}, status_code=status.HTTP_400_BAD_REQUEST)

    hashed_pw = generate_password_hash(payload.password, method="pbkdf2:sha256")
    new_user = User(name=payload.name, email=payload.email, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    request.session["user_id"] = new_user.id
    return {"status": "success", "user": new_user.name}


@app.post("/api/login")
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if user and check_password_hash(user.password_hash, payload.password):
        request.session["user_id"] = user.id
        return {"status": "success", "user": user.name}
    return JSONResponse({"status": "error", "message": "Invalid email or password"}, status_code=status.HTTP_401_UNAUTHORIZED)


@app.post("/api/logout")
def logout(request: Request):
    request.session.pop("user_id", None)
    return {"status": "success"}


# --- PRODUCT API ROUTES ---
@app.get("/api/products/top")
def get_top_products():
    if not PRODUCTS_MAP:
        return []
    top = [normalize_product(p) for p in list(PRODUCTS_MAP.values())[:20]]
    return top


@app.get("/api/search")
def search_products(q: Optional[str] = None):
    query = (q or "").lower().strip()
    if not query:
        return []

    results = []

    # 1. Brand Search
    brand_matches = [p for pid, p in PRODUCTS_MAP.items() if query == str(p.get("Brand")).lower()]
    if brand_matches:
        return [normalize_product(p) for p in brand_matches[:20]]

    # 2. Hybrid Recs
    matched_id = None
    for pid, p in PRODUCTS_MAP.items():
        if query in p.get("product_name", "").lower():
            matched_id = pid
            break

    if matched_id and matched_id in RECOMMENDATIONS:
        rec_list = RECOMMENDATIONS[matched_id]
        for rec in rec_list:
            name = rec.get("product_name")
            if name in PRODUCT_NAMES_MAP:
                results.append(PRODUCTS_MAP[PRODUCT_NAMES_MAP[name]])
        if results:
            return [normalize_product(p) for p in results[:20]]

    # 3. Fallback scoring
    scored = []
    for pid, p in PRODUCTS_MAP.items():
        score = 0
        if query in p.get("product_name", "").lower():
            score += 10
        if query in str(p.get("Brand")).lower():
            score += 5
        if score > 0:
            scored.append((score, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [normalize_product(item[1]) for item in scored[:20]]


# ---------------------
# Run with: uvicorn main:app --reload
# ---------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", reload=True)
