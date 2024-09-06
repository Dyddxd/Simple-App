from fastapi import FastAPI, Form, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeSerializer
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
import os
import mysql.connector
from mysql.connector import Error
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()

instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)

# Secret key for session management
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Initialize rate limiter with in-memory storage
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session serializer
serializer = URLSafeSerializer(SECRET_KEY)

# MySQL connection details
db_config = {
    'host': DB_HOST,
    'user': DB_USER,
    'password': DB_PASSWORD,
    'database': DB_NAME
}

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Helper function for password hashing
def hash_password(password: str):
    return pwd_context.hash(password)

# Helper function for verifying passwords
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Helper function to get a database connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error: {e}")
        return None

# Register route
@app.get("/register")
@limiter.limit("5/minute")  # Rate limit of 5 requests per minute
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
@limiter.limit("5/minute")
async def register_user(request: Request, username: str = Form(...), password: str = Form(...)):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            connection.close()
            return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists."})
        
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()
        connection.close()
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": "Database connection failed."})

# Login route
@app.get("/login")
@limiter.limit("5/minute")
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
@limiter.limit("5/minute")
async def login_user(request: Request, username: str = Form(...), password: str = Form(...)):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        connection.close()
        
        if not user or not verify_password(password, user["password"]):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})
        
        # Store session data
        request.session["user"] = serializer.dumps(username)
        
        # Redirect to profile setup if profile is incomplete
        if not user.get("description"):
            return RedirectResponse(url="/profile", status_code=302)
        
        return RedirectResponse(url="/home", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Database connection failed."})

# Profile setup route
@app.get("/profile")
@limiter.limit("5/minute")
async def profile_form(request: Request):
    user = request.session.get("user")
    if user:
        return templates.TemplateResponse("profile.html", {"request": request})
    return RedirectResponse(url="/login")

@app.post("/profile")
@limiter.limit("5/minute")
async def profile_setup(request: Request, description: str = Form(...), age: int = Form(...), occupation: str = Form(...)):
    user = request.session.get("user")
    if user:
        username = serializer.loads(user)
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE users 
                SET description = %s, age = %s, occupation = %s 
                WHERE username = %s
            """, (description, age, occupation, username))
            connection.commit()
            connection.close()
            return RedirectResponse(url="/home", status_code=302)
        return RedirectResponse(url="/profile", status_code=302, headers={"error": "Database connection failed."})
    return RedirectResponse(url="/login")

# Home route
@app.get("/home")
@limiter.limit("5/minute")
async def home(request: Request):
    user = request.session.get("user")
    if user:
        username = serializer.loads(user)
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            profile = cursor.fetchone()
            connection.close()
            return templates.TemplateResponse("home.html", {"request": request, "username": username, "profile": profile})
        return RedirectResponse(url="/home", status_code=302, headers={"error": "Database connection failed."})
    return RedirectResponse(url="/login")

# Logout route
@app.get("/logout")
@limiter.limit("5/minute")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/", status_code=302)

# Root route
@app.get("/")
@limiter.limit("5/minute")
async def root(request: Request):
    user = request.session.get("user")
    if user:
        username = serializer.loads(user)
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            profile = cursor.fetchone()
            connection.close()
            return templates.TemplateResponse("home.html", {"request": request, "username": username, "profile": profile})
        return templates.TemplateResponse("home.html", {"request": request, "username": username, "error": "Database connection failed."})
    return templates.TemplateResponse("home.html", {"request": request})
