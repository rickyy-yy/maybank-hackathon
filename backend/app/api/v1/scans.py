from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import os
import uuid
import logging

from app.database import get_db
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])
logger = logging.getLogger(__name__)

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
    source_tool: str = "auto",
    db: AsyncSession = Depends(get_db)
):
    """
    Upload and process vulnerability scan file
    
    Args:
        file: Scan file (XML, JSON, CSV, Markdown)
        source_tool: Scanner tool name (nessus, nmap, markdown, csv, auto)
    """
    # Validate file extension
    allowed_extensions = {'.xml', '.nessus', '.json', '.csv', '.md', '.markdown'}
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
    
    logger.info(f"Received upload: {file.filename} ({len(file_content)} bytes) for {source_tool}")
    
    # Save file to disk
    upload_dir = "/app/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(file_content)
    
    logger.info(f"Saved file to: {file_path}")
    
    # Create scan record
    scan_service = ScanService(db)
    scan = await scan_service.create_scan(
        filename=file.filename,
        source_tool=source_tool
    )
    
    logger.info(f"Created scan record with ID: {scan.id}")
    
    # Process scan in background
    background_tasks.add_task(
        process_scan_background,
        str(scan.id),
        file_content,
        source_tool
    )
    
    logger.info(f"Queued background processing for scan {scan.id}")
    
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
    """
    Check processing status of a scan with detailed information
    
    Returns:
        - status: 'processing', 'completed', 'failed', or 'not_found'
        - processed: boolean indicating if scan is fully processed
        - statistics: severity breakdown if completed
        - error: error message if failed
    """
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    
    scan_service = ScanService(db)
    status_info = await scan_service.get_scan_status(scan_uuid)
    
    if status_info['status'] == 'not_found':
        raise HTTPException(status_code=404, detail="Scan not found")
    
    logger.info(f"Status check for scan {scan_id}: {status_info['status']}")
    
    return status_info

async def process_scan_background(scan_id: str, file_content: bytes, source_tool: str):
    """
    Background task to process scan file
    
    This runs asynchronously after the upload completes, allowing the API
    to return immediately while processing happens in the background.
    """
    from app.database import async_session_maker
    
    logger.info(f"Background processing started for scan {scan_id}")
    
    async with async_session_maker() as db:
        scan_service = ScanService(db)
        try:
            result = await scan_service.process_scan_file(
                uuid.UUID(scan_id),
                file_content
            )
            
            if result['success']:
                logger.info(f"✅ Background processing completed successfully for scan {scan_id}")
                logger.info(f"   Findings: {result['findings_created']}")
                logger.info(f"   Statistics: {result['statistics']}")
            else:
                logger.error(f"❌ Background processing failed for scan {scan_id}: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"❌ Unexpected error in background processing for scan {scan_id}: {str(e)}", exc_info=True)