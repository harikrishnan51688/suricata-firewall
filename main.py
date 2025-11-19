from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import paramiko
from typing import Optional
import logging
import os
import sqlite3
from passlib.context import CryptContext
from datetime import datetime, timedelta
from getpass import getpass
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Suricata Rules Upload API")

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Database setup
DATABASE_URL = "sqlite:///./users.db"

def initialize_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def check_and_create_superuser():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        print("No admin user found. Creating a super user.")
        username = input("Enter admin username [admin]: ") or "admin"
        email = input("Enter admin email: ")

        while True:
            password = getpass("Enter admin password: ")
            confirm_password = getpass("Confirm admin password: ")
            if password == confirm_password:
                break
            else:
                print("Passwords do not match. Please try again.")

        hashed_password = pwd_context.hash(password)

        cursor.execute("""
                       INSERT INTO users (username, email, hashed_password, role, created_at) VALUES (?, ?, ?, 'admin', ?)
                       """, 
        (username, email, hashed_password, datetime.now()))
        conn.commit()
        print(f"Super user '{username}' created successfully.")
    conn.close()

initialize_db()
# check_and_create_superuser()

# Configuration
SSH_CONFIG = {
    "host": "10.21.232.1",
    "username": "admin",
    "key_file": os.getenv("KEY_FILE"),
    "remote_file": "/var/lib/suricata/rules/custom.rules"
}


def get_user_by_username(username: str) -> Optional[dict]:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, hashed_password, created_at, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "email": row[2],
            "hashed_password": row[3],
            "created_at": row[4],
            "role": row[5]
        }
    return None

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    if expires_delta:
        to_encode.update({"exp": expires_delta})
    else:
        to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

## User Authentication Endpoints  ##

@app.post("/signup")
async def signup(username: str, email: str, password: str):
    """Register a new user."""

    existing_user = get_user_by_username(username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        hashed_password = get_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
            (username, email, hashed_password))
        conn.commit()
        conn.close()
        return {"message": "User created successfully"}
    
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/login")
async def login(username: str, password: str):
    """Authenticate user and return JWT token."""
    user = get_user_by_username(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    token_data = {
        "username": user["username"],
    }
    
    token = create_access_token(data=token_data)
    
    return {"access_token": token, "token_type": "bearer"}

## Suricata Rules Upload Endpoints  ##

def append_rules_to_remote(content: str) -> dict:
    """
    Append rules content to the remote Suricata rules file via SFTP.
    """
    ssh = None
    sftp = None
    
    try:
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=SSH_CONFIG["host"],
            username=SSH_CONFIG["username"],
            key_filename=SSH_CONFIG["key_file"],
            #look_for_keys=False, // uncomment for password auth
            allow_agent=False
        )
        
        # Open SFTP session
        sftp = ssh.open_sftp()
        
        # Open remote file in append mode and write content
        with sftp.file(SSH_CONFIG["remote_file"], 'a') as remote:
            remote.write(content)
        
        logger.info(f"Successfully appended {len(content)} bytes to {SSH_CONFIG['remote_file']}")
        
        return {
            "status": "success",
            "bytes_written": len(content),
            "remote_file": SSH_CONFIG["remote_file"]
        }
        
    except Exception as e:
        logger.error(f"Error appending rules: {str(e)}")
        raise
        
    finally:
        # Clean up connections
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

# @app.post("/upload-rules")
# async def upload_rules(file: UploadFile = File(...), username: str = Depends(verify_token)):
#     """
#     Upload a Suricata rules file and append its content to the remote server.
#     """

#     # validate user role is admin
#     user = get_user_by_username(username)
#     if not user or user.get("role") != "admin":
#         raise HTTPException(
#             status_code=403,
#             detail="Operation not permitted. Admin access required."
#         )
    
#     # validate user role is admin
#     user = get_user_by_username(username)
#     if not user or user.get("role") != "admin":
#         raise HTTPException(
#             status_code=403,
#             detail="Operation not permitted. Admin access required."
#         )
    
#     # Validate file extension
#     if not file.filename.endswith('.rules'):
#         raise HTTPException(
#             status_code=400,
#             detail="Invalid file type. Only .rules files are accepted."
#         )
    
#     try:
#         # Read the uploaded file content
#         content = await file.read()
#         content_str = content.decode('utf-8')
        
#         # Validate content is not empty
#         if not content_str.strip():
#             raise HTTPException(
#                 status_code=400,
#                 detail="Uploaded file is empty.")
        
#         # Ensure content ends with newline
#         if not content_str.endswith('\n'):
#             content_str += '\n'
        
#         # Append to remote file
#         result = append_rules_to_remote(content_str)
        
#         return JSONResponse(
#             status_code=200,
#             content={
#                 "message": "Rules appended successfully",
#                 "filename": file.filename,
#                 "bytes_written": result["bytes_written"],
#                 "remote_file": result["remote_file"]
#             })
        
#     except UnicodeDecodeError:
#         raise HTTPException(
#             status_code=400,
#             detail="File encoding error. Please ensure the file is UTF-8 encoded."
#         )
#     except Exception as e:
#         logger.error(f"Error processing upload: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail=f"Failed to append rules: {str(e)}"
#         )

@app.post("/append-rules-text")
async def append_rules_text(rules: str, username: str = Depends(verify_token)):
    """
    Append rules content directly as text (alternative to file upload).
    """
    try:
        # validate user role is admin
        user = get_user_by_username(username)
        if not user or user.get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Operation not permitted. Admin access required."
            )
        
        # Validate content is not empty
        if not rules.strip():
            raise HTTPException(status_code=400, detail="Rules content is empty.")
        
        # Ensure content ends with newline
        if not rules.endswith('\n'):
            rules += '\n'
        
        # Append to remote file
        result = append_rules_to_remote(rules)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Rules appended successfully",
                "bytes_written": result["bytes_written"],
                "remote_file": result["remote_file"]
            }
        )
        
    except Exception as e:
        logger.error(f"Error processing text rules: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to append rules: {str(e)}"
        )

##### for automatic updation of rules
@app.post("/upload-rules")
async def upload_rules(file: UploadFile = File(...)):
    """
    Upload a Suricata rules file and append its content to the remote server.
    """
    
    # Validate file extension
    if not file.filename.endswith('.rules'):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .rules files are accepted."
        )
    
    try:
        # Read the uploaded file content
        content = await file.read()
        content_str = content.decode('utf-8')
        
        # Validate content is not empty
        if not content_str.strip():
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.")
        
        # Ensure content ends with newline
        if not content_str.endswith('\n'):
            content_str += '\n'
        
        # Append to remote file
        result = append_rules_to_remote(content_str)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Rules appended successfully",
                "filename": file.filename,
                "bytes_written": result["bytes_written"],
                "remote_file": result["remote_file"]
            })
        
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File encoding error. Please ensure the file is UTF-8 encoded."
        )
    except Exception as e:
        logger.error(f"Error processing upload: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to append rules: {str(e)}"
        )

#####
@app.get("/")
async def root():
    return {"message": "Suricata Rules Upload API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)