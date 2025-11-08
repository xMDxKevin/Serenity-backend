import os
import time
import tempfile
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client, Client
import bcrypt
import jwt
import asyncpg


load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")  # formato recomendado: postgres://user:pass@host:port/dbname?sslmode=require

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Supabase configuration missing: SUPABASE_URL or SUPABASE_ANON_KEY")
if not DATABASE_URL:
    print("")
    # Los endpoints que requieren DB devolverán 503 hasta configurarlo
# Inicialización opcional para permitir acceso a /docs sin credenciales completas
supabase: Client | None = None
if SUPABASE_URL and SUPABASE_ANON_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        print("✅ Supabase client initialized")
    except Exception as e:
        print(f"⚠️ Supabase init failed: {e}")
else:
    print("⚠️ Supabase config missing; storage features disabled.")

db_pool: asyncpg.Pool | None = None

app = FastAPI(title="Serenity Zero API", description="API de Serenity Zero", version="1.0.0")

origins = [
    "https://serenity-zz.vercel.app", 
    "http://localhost:3000", 
    "http://localhost:5173", 
]

app.add_middleware(
CORSMiddleware,
allow_origins=origins, 
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str  # puede ser username o email
    password: str


class UpdateProfileRequest(BaseModel):
    about_me: Optional[str] = None


class CreatePostRequest(BaseModel):
    message: str


security = HTTPBearer(auto_error=True)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # { userId, email, exp }
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.on_event("startup")
async def startup_event():
    global db_pool
    if not DATABASE_URL:
        print("")
        db_pool = None
    else:
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
            async with db_pool.acquire() as conn:
                await conn.execute("SELECT 1")
            print("✅ Database SQL pool initialized")
        except Exception as e:
            print(f"❌ Error initializing SQL pool: {e}")
            db_pool = None
    try:
        # Comprobación ligera de cliente de storage
        print("✅ Supabase storage client initialized")
    except Exception as e:
        print(f"❌ Error initializing Supabase client: {e}")


@app.get("/api/users")
async def get_users():
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                "age, about_me FROM users ORDER BY username ASC"
            )
        return {"users": [dict(r) for r in rows]}
    except Exception as e:
        print("Get users error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/users/{id}")
async def get_user(id: int):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, profile_image, about_me FROM users WHERE id=$1",
                id,
            )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {"user": dict(row)}
    except HTTPException:
        raise
    except Exception as e:
        print("Get user error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/forum/posts")
async def get_forum_posts():
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT p.id, p.message, p.created_at,
                       u.username AS users_username,
                       u.profile_image AS users_profiSELECT id, username, profile_imle_image
                FROM posts p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.created_at ASC
                """
            )
        posts = [
            {
                "id": r["id"],
                "message": r["message"],
                "created_at": r["created_at"],
                "users": {
                    "username": r["users_username"],
                    "profile_image": r["users_profile_image"],
                },
            }
            for r in rows
        ]
        return {"posts": posts}
    except Exception as e:
        print("Get posts error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/forum/posts")
async def create_post(payload: CreatePostRequest, user=Depends(get_current_user)):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        user_id = user.get("userId")
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO posts (user_id, message) VALUES ($1, $2) RETURNING id, user_id, message, created_at",
                user_id,
                payload.message,
            )
        return {"post": dict(row)}
    except Exception as e:
        print("Create post error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/upload/avatar")
async def upload_avatar(avatar: UploadFile = File(...), user=Depends(get_current_user)):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        if not avatar.content_type or not avatar.content_type.startswith("image/"):
            raise HTTPException(status_code=400, detail="Only image files are allowed")

        user_id = user.get("userId")
        content = await avatar.read()
        ext = avatar.filename.split(".")[-1] if avatar.filename and "." in avatar.filename else avatar.content_type.split("/")[1]
        file_name = f"avatar-{user_id}-{int(time.time())}.{ext}"

        # Intentar subir como bytes; si el cliente requiere ruta, usar archivo temporal
        try:
            upload_res = supabase.storage.from_("avatars").upload(file_name, content, file_options={"content-type": avatar.content_type})
        except Exception:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(content)
                tmp.flush()
                upload_res = supabase.storage.from_("avatars").upload(file_name, tmp.name, file_options={"content-type": avatar.content_type})

        if getattr(upload_res, "error", None):
            raise HTTPException(status_code=500, detail="Avatar upload error")

        url_res = supabase.storage.from_("avatars").get_public_url(file_name)
        public_url = None
        if hasattr(url_res, "data") and isinstance(url_res.data, dict):
            public_url = url_res.data.get("publicUrl")
        elif isinstance(url_res, dict):
            public_url = url_res.get("data", {}).get("publicUrl")
        if not public_url:
            raise HTTPException(status_code=500, detail="Failed to obtain public URL")

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE users SET profile_image=$1 WHERE id=$2 RETURNING id, username, email, about_me, profile_image",
                public_url,
                user_id,
            )

        return {"imageUrl": public_url, "user": dict(row)}
    except HTTPException:
        raise
    except Exception as e:
        print("Avatar upload error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.put("/api/auth/profile")
async def update_profile(payload: UpdateProfileRequest, user=Depends(get_current_user)):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        user_id = user.get("userId")
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE users SET about_me=$1 WHERE id=$2 RETURNING id, username, email, about_me, profile_image",
                payload.about_me,
                user_id,
            )
        return {"user": dict(row)}
    except Exception as e:
        print("Profile update error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/auth/register")
async def register(payload: RegisterRequest):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            exists = await conn.fetchrow("SELECT email FROM users WHERE email=$1", payload.email)
            if exists:
                raise HTTPException(status_code=400, detail="User already exists")

            hashed = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt())
            hashed_str = hashed.decode("utf-8")

            user_row = await conn.fetchrow(
                """
                INSERT INTO users (username, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, username, email
                """,
                payload.username,
                payload.email,
                hashed_str,
            )

        exp = int(time.time()) + 7 * 24 * 60 * 60
        token = jwt.encode({"userId": user_row["id"], "email": user_row["email"], "exp": exp}, JWT_SECRET, algorithm="HS256")

        return {
            "message": "User registered successfully",
            "token": token,
            "user": {"id": user_row["id"], "username": user_row["username"], "email": user_row["email"]},
        }
    except HTTPException:
        raise
    except Exception as e:
        print("Registration error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/auth/login")
async def login(payload: LoginRequest):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT * FROM users WHERE username=$1 OR email=$1",
                payload.username,
            )
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        ok = bcrypt.checkpw(payload.password.encode("utf-8"), user["password"].encode("utf-8"))
        if not ok:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        exp = int(time.time()) + 7 * 24 * 60 * 60
        token = jwt.encode({"userId": user["id"], "email": user["email"], "exp": exp}, JWT_SECRET, algorithm="HS256")

        return {
            "message": "Login successful",
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"]},
        }
    except HTTPException:
        raise
    except Exception as e:
        print("Login error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/auth/profile")
async def get_profile(user=Depends(get_current_user)):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, about_me, profile_image FROM users WHERE id=$1",
                user.get("userId"),
            )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {"user": dict(row)}
    except HTTPException:
        raise
    except Exception as e:
        print("Profile error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "3000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)