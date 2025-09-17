# secure-api-gateway-3046-3055

Secure RBAC API using FastAPI with JWT authentication and role-based access control.

## Features
- JWT-based authentication (OAuth2 password flow)
- Role-based access control using roles as OAuth scopes (`user`, `admin`)
- SQLite-backed user store with default users created on first run
- OpenAPI docs at `/docs`

## Endpoints
- GET `/` - Health check
- POST `/auth/login` - Obtain JWT access token
- GET `/resource/items` - Protected: requires `user` or `admin`
- GET `/resource/admin` - Protected: requires `admin`
- GET `/roles` - Protected: requires `admin`
- POST `/roles/assign` - Protected: requires `admin`

## Quick start
1. Create a virtual environment and install dependencies
   ```
   pip install -r api_backend/requirements.txt
   ```
2. Optional: copy `.env.example` to `.env` in `api_backend/` and customize.
3. Run the server:
   ```
   uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
   ```
4. Open docs at `http://localhost:8000/docs`

## Default users
- admin / admin123 (roles: admin,user)
- user / user123 (roles: user)

## Curl examples

Login as admin:
```
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  http://localhost:8000/auth/login
```

Use token:
```
TOKEN="paste_access_token_here"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/resource/items
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/resource/admin
```

Assign role:
```
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"user","role":"admin"}' \
  http://localhost:8000/roles/assign
```

## Configuration
Set the following environment variables (see `api_backend/.env.example`):
- SECRET_KEY
- ACCESS_TOKEN_EXPIRE_MINUTES
- ALGORITHM
- DATABASE_URL
- CORS_ALLOW_ORIGINS

Note: Never commit real secrets. Use environment variables in deployment.
