from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import List
import uuid

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.jira_service import JiraIntegrationService

router = APIRouter(prefix="/api/v1/integrations/jira", tags=["jira"])


class CreateTicketRequest(BaseModel):
    finding_ids: List[str]
    project_key: str


class TestConnectionResponse(BaseModel):
    connected: bool
    message: str


@router.post("/test-connection")
async def test_jira_connection() -> TestConnectionResponse:
    """Test Jira connection"""
    jira_service = JiraIntegrationService()
    
    if not jira_service.enabled:
        return TestConnectionResponse(
            connected=False,
            message="Jira integration is not configured. Please set JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables."
        )
    
    connected = jira_service.test_connection()
    
    if connected:
        return TestConnectionResponse(
            connected=True,
            message="Successfully connected to Jira"
        )
    else:
        return TestConnectionResponse(
            connected=False,
            message="Failed to connect to Jira. Please check your credentials."
        )


@router.post("/create-tickets")
async def create_jira_tickets(
    request: CreateTicketRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Create Jira tickets for multiple findings
    
    Request body:
        finding_ids: List of finding UUIDs
        project_key: Jira project key (e.g., 'SEC', 'VULN')
    """
    jira_service = JiraIntegrationService()
    
    if not jira_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="Jira integration is not configured"
        )
    
    # Validate and fetch findings
    finding_uuids = []
    for finding_id in request.finding_ids:
        try:
            finding_uuids.append(uuid.UUID(finding_id))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid finding ID format: {finding_id}"
            )
    
    # Fetch findings
    result = await db.execute(
        select(Finding).where(Finding.id.in_(finding_uuids))
    )
    findings = result.scalars().all()
    
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")
    
    # Fetch all related scans
    scan_ids = list(set([finding.source_scan_id for finding in findings]))
    scan_result = await db.execute(
        select(Scan).where(Scan.id.in_(scan_ids))
    )
    scans_list = scan_result.scalars().all()
    scans_dict = {str(scan.id): scan for scan in scans_list}
    
    # Create tickets
    results = await jira_service.create_bulk_tickets(
        findings=findings,
        scans=scans_dict,
        project_key=request.project_key
    )
    
    # Update findings with ticket information
    for created in results['created']:
        finding_id = uuid.UUID(created['finding_id'])
        finding = (await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )).scalar_one_or_none()
        
        if finding:
            finding.jira_ticket_key = created['ticket_key']
            finding.jira_ticket_url = created['ticket_url']
    
    await db.commit()
    
    return {
        'success': True,
        'total_requested': len(request.finding_ids),
        'created': len(results['created']),
        'failed': len(results['failed']),
        'tickets': results['created'],
        'errors': results['failed']
    }


@router.post("/create-ticket/{finding_id}")
async def create_single_jira_ticket(
    finding_id: str,
    project_key: str,
    db: AsyncSession = Depends(get_db)
):
    """Create a Jira ticket for a single finding"""
    jira_service = JiraIntegrationService()
    
    if not jira_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="Jira integration is not configured"
        )
    
    # Validate and fetch finding
    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid finding ID format: {finding_id}"
        )
    
    result = await db.execute(
        select(Finding).where(Finding.id == finding_uuid)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Fetch the scan
    scan_result = await db.execute(
        select(Scan).where(Scan.id == finding.source_scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Create ticket
    ticket_result = await jira_service.create_ticket_for_finding(
        finding=finding,
        scan=scan,
        project_key=project_key
    )
    
    if not ticket_result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create Jira ticket: {ticket_result['error']}"
        )
    
    # Update finding
    finding.jira_ticket_key = ticket_result['ticket_key']
    finding.jira_ticket_url = ticket_result['ticket_url']
    await db.commit()
    
    return {
        'success': True,
        'finding_id': finding_id,
        'ticket_key': ticket_result['ticket_key'],
        'ticket_url': ticket_result['ticket_url']
    }