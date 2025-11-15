from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from app.api.v1.integrations import jira
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from app.api.v1 import scans, findings

app = FastAPI(
    title="VulnForge API",
    description="Vulnerability Remediation Engine",
    version="1.0.0"
)

# CORS configuration - be more permissive for development
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

logger.info(f"CORS origins configured: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(jira.router)

@app.get("/")
async def root():
    return {
        "message": "VulnForge API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "VulnForge API is operational"
    }

# Add startup event to log configuration
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 50)
    logger.info("VulnForge API Starting")
    logger.info(f"CORS Origins: {origins}")
    logger.info(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    logger.info("=" * 50)