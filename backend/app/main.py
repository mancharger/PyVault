from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .database import engine, Base
from .routes import vault

# Create database tables
Base.metadata.create_all(bind=engine)

# Rate Limiter setup (OWASP Top 10 - DoS prevention)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="PyVault API",
    description="Zero-Knowledge API for storing encrypted blobs with immutable forensic audit trail.",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware (Restrict this in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development. Should be frontend URL in prod.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Apply rate limiting globally or per route. Let's do a global 100 requests per minute for now.
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # This is a simplified way to apply a global limit, but SlowAPI handles it better per-route.
    # We will just apply it on specific routes if needed.
    return await call_next(request)

app.include_router(vault.router, prefix="/api/vault", tags=["Vault"])

@app.get("/")
@limiter.limit("5/minute")
def read_root(request: Request):
    return {"status": "PyVault API is running securely."}
