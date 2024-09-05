from fastapi import FastAPI, Form, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeSerializer
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
import os
from dotenv import load_dotenv

app = FastAPI()

# Secret key for session management
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
print(SECRET_KEY)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session serializer
serializer = URLSafeSerializer(SECRET_KEY)

# Dummy user database
fake_db = {}

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


# Register route
@app.get("/register")
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_user(request: Request, username: str = Form(...), password: str = Form(...)):
    if username in fake_db:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists."})
    
    hashed_password = hash_password(password)
    fake_db[username] = hashed_password
    return RedirectResponse(url="/login", status_code=302)


# Login route
@app.get("/login")
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_user(request: Request, username: str = Form(...), password: str = Form(...)):
    user = fake_db.get(username)
    
    if not user or not verify_password(password, user):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})
    
    # Store session data
    request.session["user"] = serializer.dumps(username)
    return RedirectResponse(url="/home", status_code=302)


# Logout route
@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/", status_code=302)


# Home route
@app.get("/home")
async def home(request: Request):
    user = request.session.get("user")
    if user:
        username = serializer.loads(user)
        return templates.TemplateResponse("home.html", {"request": request, "username": username})
    return RedirectResponse(url="/login")


# Root route
@app.get("/")
async def root(request: Request):
    user = request.session.get("user")
    if user:
        username = serializer.loads(user)
        return templates.TemplateResponse("home.html", {"request": request, "username": username})
    return templates.TemplateResponse("home.html", {"request": request})
