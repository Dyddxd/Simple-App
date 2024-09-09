from fastapi import FastAPI, Form, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeSerializer
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
import os

from .database import get_db_connection

app = FastAPI()

# Secret key for session management
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Initialize rate limiter with in-memory storage
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session serializer
serializer = URLSafeSerializer(SECRET_KEY)

# Helper function for password hashing
def hash_password(password: str):
    return pwd_context.hash(password)

# Helper function for verifying passwords
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Register route
@app.post("/register")
@limiter.limit("5/minute")
async def register_user(username: str = Form(...), password: str = Form(...)):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            connection.close()
            raise HTTPException(status_code=400, detail="Username already exists.")
        
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()
        connection.close()
        return RedirectResponse(url="/login", status_code=302)
    raise HTTPException(status_code=500, detail="Database connection failed.")

# Login route
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
            raise HTTPException(status_code=400, detail="Invalid credentials.")
        
        # Store session data
        request.session["user"] = serializer.dumps(username)
        return RedirectResponse(url="/home", status_code=302)
    raise HTTPException(status_code=500, detail="Database connection failed.")

# Logout route
@app.get("/logout")
@limiter.limit("5/minute")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/", status_code=302)
