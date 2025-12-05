from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import random
from datetime import datetime

app = Flask(__name__)
# 🔑 SECRET KEY (Required for Sessions/Cookies)
app.secret_key = 'lumina_secret_key_change_this_in_production'

# --- 1. CONFIGURATION & DATABASE ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'artifacts')

# Database Config (Creates lumina.db in your project folder)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "lumina.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- 2. DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# --- 3. DATA LOADING (Standard) ---
PRODUCTS_MAP = {}       
PRODUCT_NAMES_MAP = {}  
RECOMMENDATIONS = {}    

def load_data():
    global PRODUCTS_MAP, RECOMMENDATIONS, PRODUCT_NAMES_MAP
    if not os.path.exists(DATA_DIR): return

    # Load Catalog
    possible_filenames = ['product_matrix.json', 'product_index_map.json']
    matrix_path = None
    for fname in possible_filenames:
        temp = os.path.join(DATA_DIR, fname)
        if os.path.exists(temp): matrix_path = temp; break
            
    if matrix_path:
        try:
            with open(matrix_path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            data_list = raw if isinstance(raw, list) else [v for k,v in raw.items()] if isinstance(raw, dict) else []
            
            for item in data_list:
                if isinstance(item, str): continue
                pid = str(item.get('product_id_numeric', item.get('product_id', 'N/A')))
                if pid != 'None':
                    PRODUCTS_MAP[pid] = item
                    PRODUCT_NAMES_MAP[item.get('product_name', '').strip()] = pid
            print(f"✅ Data Loaded: {len(PRODUCTS_MAP)} products.")
        except: pass

    # Load Recommendations
    rec_path = os.path.join(DATA_DIR, 'precomputed_hybrid.json')
    if os.path.exists(rec_path):
        try:
            with open(rec_path, 'r', encoding='utf-8') as f: RECOMMENDATIONS = json.load(f)
        except: pass

def normalize_product(p):
    try: price = float(p.get('actual_price', 0))
    except: price = 0.0
    try: disc = float(p.get('discounted_price', price))
    except: disc = price
    return {
        "p_id": str(p.get('product_id_numeric')),
        "name": p.get('product_name', 'Unknown'),
        "brand": p.get('Brand', 'Generic'),
        "rating": p.get('rating', 0),
        "prices": price,
        "discounted_price": disc,
        "img_link": p.get('img_link', ''),
        "p_link": p.get('product_link', '#')
    }

# --- 4. ROUTES ---

@app.route('/')
def home():
    # Check if user is logged in via Session
    user_name = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user: user_name = user.name
    return render_template('index.html', user_name=user_name)

# --- 🔐 AUTHENTICATION ROUTES (REAL LOGIC) ---

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"status": "error", "message": "Email already registered"}), 400

    # Secure Password Hashing
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, email=email, password_hash=hashed_pw)
    
    db.session.add(new_user)
    db.session.commit()
    
    session['user_id'] = new_user.id
    return jsonify({"status": "success", "user": name})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    # Check Password
    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return jsonify({"status": "success", "user": user.name})
    
    # ❌ If failed, send Error
    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"status": "success"})

# --- 🔍 PRODUCT API ROUTES ---

@app.route('/api/products/top')
def get_top_products():
    if not PRODUCTS_MAP: return jsonify([])
    return jsonify([normalize_product(p) for p in list(PRODUCTS_MAP.values())[:20]])

@app.route('/api/search')
def search_products():
    query = request.args.get('q', '').lower().strip()
    if not query: return jsonify([])

    results = []
    
    # 1. Brand Search
    brand_matches = [p for pid, p in PRODUCTS_MAP.items() if query == str(p.get('Brand')).lower()]
    if brand_matches:
        return jsonify([normalize_product(p) for p in brand_matches[:20]])

    # 2. Hybrid Recs
    matched_id = None
    for pid, p in PRODUCTS_MAP.items():
        if query in p.get('product_name', '').lower():
            matched_id = pid; break
            
    if matched_id and matched_id in RECOMMENDATIONS:
        rec_list = RECOMMENDATIONS[matched_id]
        for rec in rec_list:
            if rec.get('product_name') in PRODUCT_NAMES_MAP:
                results.append(PRODUCTS_MAP[PRODUCT_NAMES_MAP[rec.get('product_name')]])
        if results: return jsonify([normalize_product(p) for p in results[:20]])

    # 3. Fallback
    scored = []
    for pid, p in PRODUCTS_MAP.items():
        score = 0
        if query in p.get('product_name', '').lower(): score += 10
        if query in str(p.get('Brand')).lower(): score += 5
        if score > 0: scored.append((score, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    return jsonify([normalize_product(item[1]) for item in scored[:20]])

if __name__ == '__main__':
    # Initialize Database Table if not exists
    with app.app_context():
        db.create_all()
        print("💽 Database initialized.")
        
    load_data()
    # Changed port to 5001 to avoid 'Access Denied' / AirPlay conflict on MacOS
    app.run(debug=True, port=5001)