from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(
    title="VulnForge API",
    description="Vulnerability Remediation Engine",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "VulnForge API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "not_connected",
        "redis": "not_connected"
    }

@app.get("/api/v1/scans")
async def get_scans():
    return {
        "scans": [],
        "total": 0
    }

@app.get("/api/v1/findings")
async def get_findings():
    return {
        "findings": [],
        "total": 0
    }