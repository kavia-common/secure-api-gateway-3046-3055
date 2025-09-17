"""
FastAPI application entrypoint providing JWT authentication and role-based access control (RBAC).

This app exposes:
- POST /auth/login: Obtain a JWT access token
- GET /resource/items: Access protected resource (requires 'user' or 'admin')
- GET /resource/admin: Access admin-only resource (requires 'admin')
- GET /roles: List available roles (requires 'admin')
- POST /roles/assign: Assign a role to a user (requires 'admin')
- GET /: Health check

OpenAPI docs available at /docs. The app uses SQLite for persistence by default, configurable via environment variables.

Environment variables required (set in .env):
- SECRET_KEY: Secret used to sign JWT tokens (REQUIRED)
- ACCESS_TOKEN_EXPIRE_MINUTES: Token lifetime in minutes (default: 60)
- ALGORITHM: JWT signing algorithm (default: HS256)
- DATABASE_URL: SQLAlchemy URL (default: sqlite:///./app.db)
"""
from datetime import datetime, timedelta, timezone
import os
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import Column, Integer, String, create_engine, select, Table, MetaData
from sqlalchemy.orm import sessionmaker

# -------- Configuration via environment variables --------
SECRET_KEY = os.getenv("SECRET_KEY")  # Do not default silently; raise if missing at startup
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

if not SECRET_KEY:
    # Provide clear guidance; app will still start but auth will fail until configured.
    # For safety, generate a temporary key if not provided, but log a warning.
    # In production, ensure SECRET_KEY is provided via environment.
    SECRET_KEY = os.urandom(32).hex()

# -------- Database setup (SQLite by default) --------
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

metadata = MetaData()

# Users table with id, username, hashed_password, roles (comma-separated)
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("username", String, unique=True, index=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("roles", String, nullable=False, default="user"),  # CSV roles
)

# Create tables if not exist
metadata.create_all(bind=engine)

# Initialize default admin/user if not present
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def init_default_users():
    with SessionLocal() as db:
        existing_admin = db.execute(select(users_table).where(users_table.c.username == "admin")).fetchone()
        if not existing_admin:
            db.execute(
                users_table.insert().values(
                    username="admin",
                    hashed_password=pwd_context.hash("admin123"),
                    roles="admin,user",
                )
            )
        existing_user = db.execute(select(users_table).where(users_table.c.username == "user")).fetchone()
        if not existing_user:
            db.execute(
                users_table.insert().values(
                    username="user",
                    hashed_password=pwd_context.hash("user123"),
                    roles="user",
                )
            )
        db.commit()


init_default_users()

# -------- Security and auth helpers --------

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    scopes={
        "user": "General user access",
        "admin": "Administrative access",
    },
)

# PUBLIC_INTERFACE
class Token(BaseModel):
    """OAuth2 access token response."""
    access_token: str = Field(..., description="The JWT access token")
    token_type: str = Field(default="bearer", description="Type of the token")


# PUBLIC_INTERFACE
class TokenData(BaseModel):
    """Token data extracted from JWT."""
    username: Optional[str] = Field(None, description="Username subject in token")
    scopes: List[str] = Field(default_factory=list, description="Scopes/roles encoded in token")


# PUBLIC_INTERFACE
class User(BaseModel):
    """Public representation of a user."""
    id: int = Field(..., description="User ID")
    username: str = Field(..., description="Unique username")
    roles: List[str] = Field(default_factory=list, description="List of roles assigned to the user")


# PUBLIC_INTERFACE
class RoleAssignRequest(BaseModel):
    """Payload to assign a role to a user."""
    username: str = Field(..., description="Username to modify")
    role: str = Field(..., description="Role to assign (e.g., 'user' or 'admin')")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password for storing."""
    return pwd_context.hash(password)


def get_user_by_username(username: str) -> Optional[User]:
    """Fetch user by username from DB; return User model or None."""
    with SessionLocal() as db:
        row = db.execute(select(users_table).where(users_table.c.username == username)).fetchone()
        if not row:
            return None
        # row is RowMapping; access by column keys
        roles_csv = row._mapping["roles"] or ""
        roles = [r.strip() for r in roles_csv.split(",") if r.strip()]
        return User(
            id=row._mapping["id"],
            username=row._mapping["username"],
            roles=roles,
        )


def get_user_row(username: str):
    """Internal helper to get full row for verification."""
    with SessionLocal() as db:
        row = db.execute(select(users_table).where(users_table.c.username == username)).fetchone()
        return row._mapping if row else None


def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user credentials and return user if valid."""
    row = get_user_row(username)
    if not row:
        return None
    if not verify_password(password, row["hashed_password"]):
        return None
    roles_csv = row["roles"] or ""
    roles = [r.strip() for r in roles_csv.split(",") if r.strip()]
    return User(id=row["id"], username=row["username"], roles=roles)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to get current user with required scopes via Security
async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Decode JWT, validate scopes, and return current user."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    authenticate_value = f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        scopes: List[str] = payload.get("scopes", [])
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, scopes=scopes)
    except (JWTError, ValidationError):
        raise credentials_exception

    user = get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception

    # Enforce scopes
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


# -------- FastAPI application --------
app = FastAPI(
    title="Secure RBAC API",
    description="A FastAPI backend exposing JWT authentication and role-based access control (RBAC) over three REST endpoints.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Health check endpoint"},
        {"name": "Auth", "description": "Authentication operations"},
        {"name": "Resource", "description": "Protected resource access"},
        {"name": "Roles", "description": "Role management (admin only)"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------- Routes --------

@app.get("/", tags=["Health"], summary="Health Check", description="Returns a simple health status for the API.")
def health_check():
    """
    Health check endpoint.

    Returns:
        dict: A message indicating the API is healthy.
    """
    return {"message": "Healthy"}


# Authentication endpoints
@app.post(
    "/auth/login",
    response_model=Token,
    tags=["Auth"],
    summary="Login and obtain access token",
    description="Use OAuth2 password flow to obtain a JWT access token. Default users: admin/admin123, user/user123.",
)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Authenticate user and issue a JWT access token.

    Parameters:
        form_data.username (str): Username
        form_data.password (str): Password

    Returns:
        Token: JWT bearer token with scopes corresponding to user roles.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_scopes = user.roles[:]  # roles act as scopes
    access_token = create_access_token(
        data={"sub": user.username, "scopes": token_scopes},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


# Protected resource accessible to user or admin
@app.get(
    "/resource/items",
    tags=["Resource"],
    summary="List items (user or admin)",
    description="Protected resource; requires 'user' or 'admin' role.",
)
async def list_items(current_user: Annotated[User, Security(get_current_user, scopes=["user"])]):
    """
    List resource items for authenticated users.

    Security:
        Requires 'user' scope (users with 'admin' also satisfy this).

    Returns:
        dict: Dummy list of items with username context.
    """
    return {
        "owner": current_user.username,
        "items": [
            {"id": 1, "name": "Item One"},
            {"id": 2, "name": "Item Two"},
        ],
        "roles": current_user.roles,
    }


# Admin-only resource
@app.get(
    "/resource/admin",
    tags=["Resource"],
    summary="Admin-only resource",
    description="Protected resource; requires 'admin' role.",
)
async def admin_resource(current_user: Annotated[User, Security(get_current_user, scopes=["admin"])]):
    """
    Admin-only data.

    Security:
        Requires 'admin' scope.

    Returns:
        dict: Administrative data.
    """
    return {
        "message": f"Hello, {current_user.username}. This is admin-only data.",
        "audit": {"active_users": 2, "config_version": "v1"},
    }


# Role management: list roles (admin)
@app.get(
    "/roles",
    tags=["Roles"],
    summary="List available roles",
    description="Returns the list of available roles in the system. Admin only.",
)
async def list_roles(_: Annotated[User, Security(get_current_user, scopes=["admin"])]):
    """
    Lists supported roles.

    Security:
        Requires 'admin' scope.

    Returns:
        dict: List of roles supported by the system.
    """
    return {"roles": ["user", "admin"]}


# Role management: assign role (admin)
@app.post(
    "/roles/assign",
    tags=["Roles"],
    summary="Assign a role to a user",
    description="Assign a role to a user. Admin only.",
)
async def assign_role(
    payload: RoleAssignRequest,
    _: Annotated[User, Security(get_current_user, scopes=["admin"])],
):
    """
    Assign a role to a specific user.

    Parameters:
        payload.username (str): Target username
        payload.role (str): Role to assign

    Security:
        Requires 'admin' scope.

    Returns:
        dict: Updated user with roles.
    """
    role = payload.role.strip().lower()
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    with SessionLocal() as db:
        row = db.execute(select(users_table).where(users_table.c.username == payload.username)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        current_roles_csv = row._mapping["roles"] or ""
        roles = {r.strip() for r in current_roles_csv.split(",") if r.strip()}
        roles.add(role)
        updated_roles_csv = ",".join(sorted(roles))
        db.execute(
            users_table.update()
            .where(users_table.c.id == row._mapping["id"])
            .values(roles=updated_roles_csv)
        )
        db.commit()

        return {
            "id": row._mapping["id"],
            "username": row._mapping["username"],
            "roles": sorted(list(roles)),
        }
