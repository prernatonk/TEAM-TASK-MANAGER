from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

# ======================
# Config
# ======================

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ======================
# In-memory databases
# ======================

users_db = []
projects_db = []
tasks_db = []

# ======================
# Models
# ======================

class User(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # Admin / Member


class LoginUser(BaseModel):
    email: EmailStr
    password: str


class Project(BaseModel):
    name: str
    description: str


class Task(BaseModel):
    title: str
    description: str
    assigned_to: str
    status: str  # Todo / In Progress / Done


# ======================
# Auth Utility
# ======================

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")


# ======================
# Routes
# ======================

@app.get("/")
def home():
    return {"message": "Server is running successfully 🚀"}


# ---------- SIGNUP ----------
@app.post("/signup")
def signup(user: User):
    hashed_password = pwd_context.hash(user.password)

    user_data = {
        "name": user.name,
        "email": user.email,
        "password": hashed_password,
        "role": user.role
    }

    users_db.append(user_data)
    return {"message": "User created successfully"}


# ---------- LOGIN ----------
@app.post("/login")
def login(user: LoginUser):
    for u in users_db:
        if u["email"] == user.email:

            if pwd_context.verify(user.password, u["password"]):

                token_data = {
                    "sub": u["email"],
                    "role": u["role"],
                    "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                }

                token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

                return {
                    "access_token": token,
                    "token_type": "bearer"
                }

            else:
                raise HTTPException(status_code=400, detail="Invalid password")

    raise HTTPException(status_code=404, detail="User not found")


# ---------- ADMIN ROUTE ----------
@app.get("/admin-dashboard")
def admin_dashboard(user=Depends(get_current_user)):

    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Access denied")

    return {"message": "Welcome Admin 🚀"}


# ---------- PROJECTS ----------
@app.post("/projects")
def create_project(project: Project, user=Depends(get_current_user)):

    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Only Admin can create project")

    project_data = {
        "id": len(projects_db) + 1,
        "name": project.name,
        "description": project.description,
        "created_by": user["sub"]
    }

    projects_db.append(project_data)
    return project_data


@app.get("/projects")
def get_projects():
    return projects_db


# ---------- TASKS ----------
@app.post("/tasks")
def create_task(task: Task, user=Depends(get_current_user)):

    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Only Admin can assign tasks")

    task_data = {
        "id": len(tasks_db) + 1,
        "title": task.title,
        "description": task.description,
        "assigned_to": task.assigned_to,
        "status": task.status
    }

    tasks_db.append(task_data)
    return task_data


@app.get("/tasks")
def get_tasks():
    return tasks_db


@app.patch("/tasks/{task_id}")
def update_task(task_id: int, status: str, user=Depends(get_current_user)):

    for task in tasks_db:
        if task["id"] == task_id:

            if task["assigned_to"] != user["sub"]:
                raise HTTPException(status_code=403, detail="Not allowed")

            task["status"] = status
            return task

    raise HTTPException(status_code=404, detail="Task not found")


# ---------- DEBUG ----------
@app.get("/users")
def get_users():
    return users_db