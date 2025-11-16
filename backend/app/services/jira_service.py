from typing import List, Dict, Optional
import logging
from atlassian import Jira

from app.models.finding import Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)


class JiraIntegrationService:
    """Service for creating and managing Jira tickets for findings"""

    def __init__(self, jira_config: Dict[str, Optional[str]] = None):
        """
        Initialize Jira service with configuration
        
        Args:
            jira_config: Dictionary with jira_url, jira_email, jira_api_token, jira_enabled
        """
        if jira_config:
            self.jira_url = jira_config.get("jira_url")
            self.jira_email = jira_config.get("jira_email")
            self.jira_token = jira_config.get("jira_api_token")
            self.enabled = jira_config.get("jira_enabled", False)
        else:
            self.jira_url = None
            self.jira_email = None
            self.jira_token = None
            self.enabled = False

        # Validate we have all required fields if enabled
        if self.enabled:
            if not all([self.jira_url, self.jira_email, self.jira_token]):
                logger.warning("Jira is enabled but missing required configuration")
                self.enabled = False

        if self.enabled:
            try:
                self.jira = Jira(
                    url=self.jira_url,
                    username=self.jira_email,
                    password=self.jira_token,
                    cloud=True
                )
            except Exception as e:
                logger.error(f"Failed to initialize Jira client: {str(e)}")
                self.enabled = False
        else:
            logger.info("Jira integration not enabled or not configured")

    def format_remediation_guidance(self, guidance: str) -> str:
        """
        Convert remediation guidance to Jira-friendly formatting
        
        Converts markdown-style formatting to Jira wiki markup:
        - **text** -> *text* (bold)
        - # Header -> h3. Header
        - Bullet points maintained as -
        - Code blocks to {code} blocks
        """
        if not guidance:
            return ""

        lines = guidance.split('\n')
        formatted_lines = []
        in_code_block = False
        code_language = None

        for line in lines:
            stripped = line.strip()

            # Handle code blocks
            if stripped.startswith('```'):
                if not in_code_block:
                    # Starting code block
                    lang = stripped[3:].strip() or 'python'
                    code_language = lang
                    formatted_lines.append(f'{{code:{lang}}}')
                    in_code_block = True
                else:
                    # Ending code block
                    formatted_lines.append('{code}')
                    in_code_block = False
                    code_language = None
                continue

            if in_code_block:
                formatted_lines.append(line)
                continue

            # Convert markdown bold to Jira bold
            line = line.replace('**', '*')

            # Convert headers
            if stripped.startswith('###'):
                line = 'h4. ' + stripped[3:].strip()
            elif stripped.startswith('##'):
                line = 'h3. ' + stripped[2:].strip()
            elif stripped.startswith('#'):
                line = 'h2. ' + stripped[1:].strip()

            # Handle bullet points (already compatible with Jira)
            # Jira uses - for bullets, same as markdown

            formatted_lines.append(line)

        return '\n'.join(formatted_lines)

    async def create_ticket_for_finding(
        self,
        finding: Finding,
        scan: Scan,
        project_key: str
    ) -> Dict:
        """
        Create a Jira ticket for a single finding
        
        Args:
            finding: Finding object
            scan: Scan object containing source file information
            project_key: Jira project key (e.g., 'SEC', 'VULN')
            
        Returns:
            Dictionary with ticket information
        """
        if not self.enabled:
            raise ValueError("Jira integration is not configured")

        try:
            # Map severity to priority
            priority_map = {
                'CRITICAL': 'Highest',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low',
                'INFO': 'Lowest'
            }
            priority = priority_map.get(finding.severity, 'Medium')

            # Format the description with better structure
            description = self._build_ticket_description(finding, scan)

            # Create the ticket
            issue_dict = {
                'project': {'key': project_key},
                'summary': f"[{finding.severity}] {finding.title}",
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': {'name': priority},
                'labels': [
                    'security',
                    'vulnerability',
                    finding.severity.lower(),
                    scan.source_tool.lower()
                ]
            }

            # Add CVE as label if present
            if finding.cve_id:
                issue_dict['labels'].append(finding.cve_id.replace('-', '_'))

            # Add component if service is identified
            if finding.service:
                issue_dict['components'] = [{'name': finding.service}]

            result = self.jira.issue_create(fields=issue_dict)
            ticket_key = result['key']
            ticket_url = f"{self.jira_url}/browse/{ticket_key}"

            logger.info(f"Created Jira ticket {ticket_key} for finding {finding.id}")

            return {
                'ticket_key': ticket_key,
                'ticket_url': ticket_url,
                'success': True
            }

        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def _build_ticket_description(self, finding: Finding, scan: Scan) -> str:
        """Build comprehensive Jira ticket description"""
        parts = []

        # Header with source information
        parts.append("h2. Vulnerability Details")
        parts.append(f"*Scan File:* {scan.filename}")
        parts.append(f"*Scanner Tool:* {scan.source_tool.upper()}")
        parts.append(f"*Scan Date:* {scan.upload_date.strftime('%Y-%m-%d %H:%M:%S')}")
        parts.append("")

        # Vulnerability information
        parts.append("h3. Overview")
        parts.append(f"*Severity:* {finding.severity}")
        if finding.cvss_score:
            parts.append(f"*CVSS Score:* {finding.cvss_score}")
        if finding.cve_id:
            parts.append(f"*CVE:* [{finding.cve_id}|https://nvd.nist.gov/vuln/detail/{finding.cve_id}]")
        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace('CWE-', '')
            parts.append(f"*CWE:* [{finding.cwe_id}|https://cwe.mitre.org/data/definitions/{cwe_num}.html]")
        parts.append("")

        # Affected system
        parts.append("h3. Affected System")
        parts.append(f"*Host:* {finding.affected_asset}")
        if finding.asset_hostname:
            parts.append(f"*Hostname:* {finding.asset_hostname}")
        if finding.port:
            parts.append(f"*Port:* {finding.port}/{finding.protocol}")
        if finding.service:
            parts.append(f"*Service:* {finding.service}")
        parts.append("")

        # Description
        if finding.description:
            parts.append("h3. Description")
            parts.append(finding.description)
            parts.append("")

        # Evidence
        if finding.evidence:
            parts.append("h3. Evidence")
            parts.append("{code}")
            parts.append(finding.evidence[:2000])  # Limit evidence length
            if len(finding.evidence) > 2000:
                parts.append("... (truncated)")
            parts.append("{code}")
            parts.append("")

        # Remediation guidance
        if finding.remediation_guidance:
            parts.append("h3. Remediation Guidance")
            formatted_guidance = self.format_remediation_guidance(finding.remediation_guidance)
            parts.append(formatted_guidance)
            
            if finding.effort_hours:
                parts.append("")
                parts.append(f"*Estimated Effort:* {finding.effort_hours} hours")
            parts.append("")

        # Priority information
        if finding.priority_rank:
            parts.append("h3. Priority Information")
            parts.append(f"*Risk Score:* {finding.risk_score}/100")
            parts.append(f"*Priority Rank:* #{finding.priority_rank}")
            parts.append("")

        # Additional metadata
        parts.append("h3. Additional Information")
        parts.append(f"*Finding ID:* {finding.id}")
        parts.append(f"*Detection Date:* {finding.detected_date.strftime('%Y-%m-%d %H:%M:%S')}")
        parts.append(f"*Status:* {finding.status.replace('_', ' ').title()}")

        return '\n'.join(parts)

    async def create_bulk_tickets(
        self,
        findings: List[Finding],
        scans: Dict[str, Scan],
        project_key: str
    ) -> Dict:
        """
        Create Jira tickets for multiple findings
        
        Args:
            findings: List of Finding objects
            scans: Dictionary mapping scan_id to Scan objects
            project_key: Jira project key
            
        Returns:
            Dictionary with results
        """
        if not self.enabled:
            raise ValueError("Jira integration is not configured")

        results = {
            'created': [],
            'failed': [],
            'total': len(findings)
        }

        for finding in findings:
            scan = scans.get(str(finding.source_scan_id))
            if not scan:
                logger.warning(f"Scan not found for finding {finding.id}")
                results['failed'].append({
                    'finding_id': str(finding.id),
                    'error': 'Scan not found'
                })
                continue

            result = await self.create_ticket_for_finding(finding, scan, project_key)
            
            if result['success']:
                results['created'].append({
                    'finding_id': str(finding.id),
                    'ticket_key': result['ticket_key'],
                    'ticket_url': result['ticket_url']
                })
            else:
                results['failed'].append({
                    'finding_id': str(finding.id),
                    'error': result['error']
                })

        logger.info(
            f"Bulk ticket creation complete: {len(results['created'])} created, "
            f"{len(results['failed'])} failed"
        )

        return results

    def test_connection(self) -> bool:
        """Test Jira connection"""
        if not self.enabled:
            return False

        try:
            self.jira.myself()
            return True
        except Exception as e:
            logger.error(f"Jira connection test failed: {str(e)}")
            return False