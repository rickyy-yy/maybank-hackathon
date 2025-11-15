from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import List, Optional
from pydantic import BaseModel
import logging
import uuid

from app.database import get_db
from app.models.finding import Finding
from app.services.jira_service import JiraService

router = APIRouter(prefix="/api/v1/integrations/jira", tags=["jira"])
logger = logging.getLogger(__name__)


class CreateTicketsRequest(BaseModel):
    finding_ids: List[str]
    project_key: str
    issue_type: str = "Bug"
    priority: str = "High"
    assignee: Optional[str] = None
    labels: List[str] = ["security", "vulnerability"]
    additional_description: Optional[str] = None


class TicketResponse(BaseModel):
    key: str
    url: str
    finding_id: str


@router.post("/create-tickets")
async def create_jira_tickets(
    request: CreateTicketsRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Create Jira tickets for one or more findings
    
    Args:
        request: Ticket creation parameters
        
    Returns:
        List of created tickets with keys and URLs
    """
    try:
        # Initialize Jira service
        jira_service = JiraService()
        
        # Validate Jira connection
        if not jira_service.is_configured():
            raise HTTPException(
                status_code=400,
                detail="Jira integration not configured. Please set JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN in environment variables."
            )
        
        # Get all findings
        finding_uuids = [uuid.UUID(fid) for fid in request.finding_ids]
        result = await db.execute(
            select(Finding).where(Finding.id.in_(finding_uuids))
        )
        findings = result.scalars().all()
        
        if not findings:
            raise HTTPException(status_code=404, detail="No findings found with provided IDs")
        
        logger.info(f"Creating Jira tickets for {len(findings)} findings")
        
        # Create tickets
        created_tickets = []
        for finding in findings:
            try:
                ticket = await jira_service.create_ticket_for_finding(
                    finding=finding,
                    project_key=request.project_key,
                    issue_type=request.issue_type,
                    priority=request.priority,
                    assignee=request.assignee,
                    labels=request.labels,
                    additional_description=request.additional_description
                )
                
                # Update finding with Jira ticket info
                await db.execute(
                    update(Finding)
                    .where(Finding.id == finding.id)
                    .values(
                        jira_ticket_key=ticket['key'],
                        jira_ticket_url=ticket['url']
                    )
                )
                
                created_tickets.append({
                    'key': ticket['key'],
                    'url': ticket['url'],
                    'finding_id': str(finding.id)
                })
                
                logger.info(f"Created ticket {ticket['key']} for finding {finding.id}")
                
            except Exception as e:
                logger.error(f"Failed to create ticket for finding {finding.id}: {str(e)}")
                # Continue with other findings even if one fails
                continue
        
        await db.commit()
        
        if not created_tickets:
            raise HTTPException(
                status_code=500,
                detail="Failed to create any Jira tickets. Check logs for details."
            )
        
        return {
            'success': True,
            'tickets': created_tickets,
            'total_created': len(created_tickets)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating Jira tickets: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create Jira tickets: {str(e)}"
        )


@router.get("/config")
async def get_jira_config():
    """Get Jira configuration status (without sensitive data)"""
    jira_service = JiraService()
    
    return {
        'configured': jira_service.is_configured(),
        'url': jira_service.jira_url if jira_service.is_configured() else None
    }


@router.post("/test-connection")
async def test_jira_connection():
    """Test Jira connection"""
    try:
        jira_service = JiraService()
        
        if not jira_service.is_configured():
            return {
                'success': False,
                'message': 'Jira not configured'
            }
        
        # Test connection by getting server info
        is_connected = await jira_service.test_connection()
        
        if is_connected:
            return {
                'success': True,
                'message': 'Successfully connected to Jira'
            }
        else:
            return {
                'success': False,
                'message': 'Failed to connect to Jira'
            }
            
    except Exception as e:
        logger.error(f"Jira connection test failed: {str(e)}")
        return {
            'success': False,
            'message': str(e)
        }