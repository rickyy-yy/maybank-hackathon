from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List
import uuid

from app.database import get_db
from app.models.finding import Finding

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

@router.get("")
async def get_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = Query(None, regex="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    status: Optional[str] = Query(None, regex="^(open|in_progress|resolved|false_positive)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Get findings with optional filters
    
    Query Parameters:
        scan_id: Filter by scan UUID
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        status: Filter by status (open, in_progress, resolved, false_positive)
        limit: Maximum number of results (1-500)
        offset: Number of results to skip
    """
    query = select(Finding)
    
    # Apply filters
    if scan_id:
        try:
            scan_uuid = uuid.UUID(scan_id)
            query = query.where(Finding.source_scan_id == scan_uuid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")
    
    if severity:
        query = query.where(Finding.severity == severity.upper())
    
    if status:
        query = query.where(Finding.status == status)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination and ordering
    query = query.order_by(Finding.priority_rank.nullslast(), Finding.cvss_score.desc()).limit(limit).offset(offset)
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return {
        "findings": [
            {
                "id": str(finding.id),
                "scan_id": str(finding.source_scan_id),
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
                "cve_id": finding.cve_id,
                "cwe_id": finding.cwe_id,
                "affected_asset": finding.affected_asset,
                "asset_hostname": finding.asset_hostname,
                "port": finding.port,
                "protocol": finding.protocol,
                "service": finding.service,
                "evidence": finding.evidence,
                "remediation_guidance": finding.remediation_guidance,
                "effort_hours": finding.effort_hours,
                "status": finding.status,
                "priority_rank": finding.priority_rank,
                "risk_score": finding.risk_score,
                "jira_ticket_key": finding.jira_ticket_key,
                "jira_ticket_url": finding.jira_ticket_url,
                "detected_date": finding.detected_date.isoformat() if finding.detected_date else None
            }
            for finding in findings
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "returned": len(findings)
    }

@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get specific finding by ID"""
    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format")
    
    result = await db.execute(
        select(Finding).where(Finding.id == finding_uuid)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return {
        "id": str(finding.id),
        "scan_id": str(finding.source_scan_id),
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "affected_asset": finding.affected_asset,
        "asset_hostname": finding.asset_hostname,
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
        "evidence": finding.evidence,
        "remediation_guidance": finding.remediation_guidance,
        "effort_hours": finding.effort_hours,
        "status": finding.status,
        "priority_rank": finding.priority_rank,
        "risk_score": finding.risk_score,
        "jira_ticket_key": finding.jira_ticket_key,
        "jira_ticket_url": finding.jira_ticket_url,
        "detected_date": finding.detected_date.isoformat() if finding.detected_date else None,
        "resolved_date": finding.resolved_date.isoformat() if finding.resolved_date else None
    }