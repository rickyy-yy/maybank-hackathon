import os
import logging
from typing import Optional, Dict, List
import httpx
import base64
from app.models.finding import Finding

logger = logging.getLogger(__name__)


class JiraService:
    """Service for creating and managing Jira tickets"""
    
    def __init__(self):
        self.jira_url = os.getenv('JIRA_URL', '').rstrip('/')
        self.jira_email = os.getenv('JIRA_EMAIL', '')
        self.jira_api_token = os.getenv('JIRA_API_TOKEN', '')
        
    def is_configured(self) -> bool:
        """Check if Jira is properly configured"""
        return bool(self.jira_url and self.jira_email and self.jira_api_token)
    
    def _get_auth_header(self) -> str:
        """Generate Basic Auth header"""
        auth_str = f"{self.jira_email}:{self.jira_api_token}"
        auth_bytes = auth_str.encode('ascii')
        base64_bytes = base64.b64encode(auth_bytes)
        base64_str = base64_bytes.decode('ascii')
        return f"Basic {base64_str}"
    
    async def test_connection(self) -> bool:
        """Test connection to Jira"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.jira_url}/rest/api/3/myself",
                    headers={
                        "Authorization": self._get_auth_header(),
                        "Content-Type": "application/json",
                    },
                    timeout=10.0
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Jira connection test failed: {str(e)}")
            return False
    
    async def create_ticket_for_finding(
        self,
        finding: Finding,
        project_key: str,
        issue_type: str = "Bug",
        priority: str = "High",
        assignee: Optional[str] = None,
        labels: Optional[List[str]] = None,
        additional_description: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Create a Jira ticket for a vulnerability finding
        
        Args:
            finding: Finding object
            project_key: Jira project key
            issue_type: Type of issue (Bug, Task, etc.)
            priority: Priority level
            assignee: Email of assignee (optional)
            labels: List of labels (optional)
            additional_description: Extra context to add
            
        Returns:
            Dictionary with ticket key and URL
        """
        if not self.is_configured():
            raise ValueError("Jira is not configured")
        
        # Build ticket summary
        summary = f"[{finding.severity}] {finding.title[:100]}"
        
        # Build detailed description
        description_parts = []
        
        # Add vulnerability details
        description_parts.append({
            "type": "heading",
            "attrs": {"level": 2},
            "content": [{"type": "text", "text": "Vulnerability Details"}]
        })
        
        description_parts.append({
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "Severity: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": finding.severity}
            ]
        })
        
        if finding.cvss_score:
            description_parts.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "CVSS Score: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": str(finding.cvss_score)}
                ]
            })
        
        if finding.cve_id:
            description_parts.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "CVE ID: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": finding.cve_id}
                ]
            })
        
        # Add asset information
        description_parts.append({
            "type": "heading",
            "attrs": {"level": 2},
            "content": [{"type": "text", "text": "Affected Asset"}]
        })
        
        asset_info = f"{finding.affected_asset}"
        if finding.port:
            asset_info += f" (Port {finding.port}/{finding.protocol})"
        
        description_parts.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": asset_info}]
        })
        
        # Add description
        if finding.description:
            description_parts.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": "Description"}]
            })
            description_parts.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": finding.description}]
            })
        
        # Add evidence
        if finding.evidence:
            description_parts.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": "Evidence"}]
            })
            description_parts.append({
                "type": "codeBlock",
                "content": [{"type": "text", "text": finding.evidence[:500]}]
            })
        
        # Add remediation guidance
        if finding.remediation_guidance:
            description_parts.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": "Remediation Guidance"}]
            })
            description_parts.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": finding.remediation_guidance[:1000]}]
            })
        
        # Add additional description
        if additional_description:
            description_parts.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": "Additional Notes"}]
            })
            description_parts.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": additional_description}]
            })
        
        # Build the ticket payload
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": description_parts
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
            }
        }
        
        # Add labels if provided
        if labels:
            payload["fields"]["labels"] = labels
        
        # Add assignee if provided
        if assignee:
            payload["fields"]["assignee"] = {"emailAddress": assignee}
        
        # Create the ticket
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.jira_url}/rest/api/3/issue",
                    json=payload,
                    headers={
                        "Authorization": self._get_auth_header(),
                        "Content-Type": "application/json",
                    },
                    timeout=30.0
                )
                
                if response.status_code not in [200, 201]:
                    logger.error(f"Jira API error: {response.status_code} - {response.text}")
                    raise Exception(f"Failed to create Jira ticket: {response.text}")
                
                result = response.json()
                ticket_key = result['key']
                ticket_url = f"{self.jira_url}/browse/{ticket_key}"
                
                logger.info(f"Created Jira ticket {ticket_key} for finding {finding.id}")
                
                return {
                    'key': ticket_key,
                    'url': ticket_url,
                    'id': result['id']
                }
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error creating Jira ticket: {str(e)}")
            raise Exception(f"Failed to create Jira ticket: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating Jira ticket: {str(e)}", exc_info=True)
            raise
