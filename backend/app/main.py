"""
Main FastAPI Application Entrypoint.
Initializes middleware, routing, CORS, exception handlers, and model warmup.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.ml.model_loader import ModelLoader
from app.api.v1.endpoints.analyze import router as analyze_router
from app.api.v1.endpoints.history import router as history_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.benchmark import router as benchmark_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize and warm up ML model
    print(f"[*] Starting {settings.APP_NAME} v{settings.APP_VERSION}...")
    loader = ModelLoader.get_instance()
    print(f"[+] Loaded ML model v{loader.model_version} (Algorithm: {loader.metadata.get('algorithm')})")
    yield
    print(f"[*] Shutting down {settings.APP_NAME}...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Explainable Hybrid Phishing Website Detection API using URL, Domain, HTML, and Threat-Intelligence Features.",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected server error occurred during analysis.",
            "detail": str(exc) if settings.DEBUG else None
        }
    )


# Include API v1 Routers
app.include_router(analyze_router, prefix="/api/v1", tags=["Analysis"])
app.include_router(history_router, prefix="/api/v1", tags=["History"])
app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(benchmark_router, prefix="/api/v1", tags=["Benchmark"])


@app.get("/", tags=["Root"])
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "api_v1": "/api/v1"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
