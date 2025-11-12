from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import os
import uuid

from app.database import get_db
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

@router.get("")
async def get_scans(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Get all scans with pagination"""
    scan_service = ScanService(db)
    scans = await scan_service.get_all_scans(limit=limit, offset=offset)
    
    return {
        "scans": [
            {
                "id": str(scan.id),
                "filename": scan.filename,
                "source_tool": scan.source_tool,
                "upload_date": scan.upload_date.isoformat(),
                "total_findings": scan.total_findings,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "info_count": scan.info_count,
                "processed": scan.processed,
                "processing_error": scan.processing_error
            }
            for scan in scans
        ],
        "total": len(scans),
        "limit": limit,
        "offset": offset
    }

@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get specific scan by ID"""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    
    scan_service = ScanService(db)
    scan = await scan_service.get_scan(scan_uuid)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "id": str(scan.id),
        "filename": scan.filename,
        "source_tool": scan.source_tool,
        "upload_date": scan.upload_date.isoformat(),
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "processed": scan.processed,
        "processing_error": scan.processing_error
    }

@router.post("/upload")
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source_tool: str = "nessus",
    db: AsyncSession = Depends(get_db)
):
    """
    Upload and process vulnerability scan file
    
    Args:
        file: Scan file (XML, JSON, CSV)
        source_tool: Scanner tool name (nessus, burp, nmap)
    """
    # Validate file extension
    allowed_extensions = {'.xml', '.nessus', '.json', '.csv'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        )
    
    # Read file content
    file_content = await file.read()
    
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
    # Save file to disk
    upload_dir = "/app/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(file_content)
    
    # Create scan record
    scan_service = ScanService(db)
    scan = await scan_service.create_scan(
        filename=file.filename,
        source_tool=source_tool
    )
    
    # Process scan in background
    background_tasks.add_task(
        process_scan_background,
        str(scan.id),
        file_content,
        source_tool
    )
    
    return {
        "scan_id": str(scan.id),
        "filename": file.filename,
        "source_tool": source_tool,
        "status": "processing",
        "message": "File uploaded successfully. Processing in background."
    }

@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Check processing status of a scan"""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    
    scan_service = ScanService(db)
    scan = await scan_service.get_scan(scan_uuid)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = "completed" if scan.processed else "processing"
    if scan.processing_error:
        status = "failed"
    
    return {
        "scan_id": str(scan.id),
        "status": status,
        "processed": scan.processed,
        "total_findings": scan.total_findings,
        "error": scan.processing_error,
        "statistics": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count
        } if scan.processed else None
    }

async def process_scan_background(scan_id: str, file_content: bytes, source_tool: str):
    """Background task to process scan file"""
    from app.database import async_session_maker
    
    async with async_session_maker() as db:
        scan_service = ScanService(db)
        try:
            await scan_service.process_scan_file(
                uuid.UUID(scan_id),
                file_content
            )
        except Exception as e:
            print(f"Error processing scan {scan_id}: {str(e)}")