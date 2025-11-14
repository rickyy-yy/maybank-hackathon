from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, Dict
import logging

from app.models.finding import Finding
from app.models.template import RemediationTemplate

logger = logging.getLogger(__name__)

class RemediationService:
    """Service for matching findings to remediation guidance"""
    
    # CWE to remediation mapping
    CWE_REMEDIATION_MAP = {
        'CWE-89': 'sql_injection',
        'CWE-79': 'xss',
        'CWE-78': 'command_injection',
        'CWE-287': 'authentication',
        'CWE-798': 'hardcoded_credentials',
        'CWE-327': 'weak_crypto',
        'CWE-311': 'missing_encryption',
        'CWE-352': 'csrf',
        'CWE-22': 'path_traversal',
        'CWE-434': 'file_upload',
    }
    
    # Plugin name pattern to remediation type
    PATTERN_REMEDIATION_MAP = {
        'sql injection': 'sql_injection',
        'xss': 'xss',
        'cross-site scripting': 'xss',
        'ssl': 'ssl_tls',
        'tls': 'ssl_tls',
        'certificate': 'ssl_tls',
        'weak cipher': 'weak_crypto',
        'default password': 'default_credentials',
        'default credential': 'default_credentials',
        'weak password': 'weak_password',
        'authentication': 'authentication',
        'ssh weak': 'ssh_hardening',
        'rdp': 'rdp_hardening',
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_remediation_for_finding(self, finding: Finding) -> Optional[str]:
        """
        Get remediation guidance for a specific finding
        
        Args:
            finding: Finding object
            
        Returns:
            Remediation guidance text or None
        """
        # Try to match by CWE first
        if finding.cwe_id:
            remediation = await self._get_remediation_by_cwe(finding.cwe_id)
            if remediation:
                return remediation
        
        # Try to match by plugin name pattern
        if finding.title:
            remediation = await self._get_remediation_by_pattern(finding.title)
            if remediation:
                return remediation
        
        # Try to match by CVE (future enhancement)
        if finding.cve_id:
            remediation = await self._get_remediation_by_cve(finding.cve_id)
            if remediation:
                return remediation
        
        # Return generic remediation based on severity
        return self._get_generic_remediation(finding)
    
    async def _get_remediation_by_cwe(self, cwe_id: str) -> Optional[str]:
        """Get remediation template by CWE ID"""
        result = await self.db.execute(
            select(RemediationTemplate).where(RemediationTemplate.cwe_id == cwe_id)
        )
        template = result.scalar_one_or_none()
        
        if template:
            return self._format_remediation(template)
        
        return None
    
    async def _get_remediation_by_pattern(self, title: str) -> Optional[str]:
        """Match remediation by searching for patterns in title"""
        title_lower = title.lower()
        
        for pattern, remediation_type in self.PATTERN_REMEDIATION_MAP.items():
            if pattern in title_lower:
                result = await self.db.execute(
                    select(RemediationTemplate).where(
                        RemediationTemplate.vulnerability_type.ilike(f'%{remediation_type}%')
                    )
                )
                template = result.scalar_one_or_none()
                
                if template:
                    return self._format_remediation(template)
        
        return None
    
    async def _get_remediation_by_cve(self, cve_id: str) -> Optional[str]:
        """Get remediation by CVE (placeholder for future NVD integration)"""
        # Future: Query NVD API for specific CVE remediation
        return None
    
    def _format_remediation(self, template: RemediationTemplate) -> str:
        """Format remediation template into guidance text"""
        parts = []
        
        if template.description:
            parts.append(f"**Issue:** {template.description}")
        
        if template.remediation_steps:
            parts.append(f"\n**Remediation Steps:**\n{template.remediation_steps}")
        
        if template.code_examples:
            parts.append(f"\n**Code Examples:**\n{template.code_examples}")
        
        if template.effort_hours:
            parts.append(f"\n**Estimated Effort:** {template.effort_hours} hours")
        
        if template.references:
            refs = '\n'.join([f"- {ref}" for ref in template.references])
            parts.append(f"\n**References:**\n{refs}")
        
        return '\n'.join(parts)
    
    def _get_generic_remediation(self, finding: Finding) -> str:
        """Generate generic remediation guidance based on severity and description"""
        severity = finding.severity
        
        guidance = f"**Severity:** {severity}\n\n"
        
        if severity == 'CRITICAL':
            guidance += "**Urgency:** Immediate action required. This vulnerability poses a critical risk to your systems.\n\n"
        elif severity == 'HIGH':
            guidance += "**Urgency:** High priority. Address this vulnerability within 7 days.\n\n"
        elif severity == 'MEDIUM':
            guidance += "**Urgency:** Medium priority. Address this vulnerability within 30 days.\n\n"
        else:
            guidance += "**Urgency:** Low priority. Address during regular maintenance cycles.\n\n"
        
        guidance += "**General Recommendations:**\n"
        guidance += "1. Review the vulnerability description and evidence carefully\n"
        guidance += "2. Consult vendor security advisories for patches\n"
        guidance += "3. Test fixes in a non-production environment first\n"
        guidance += "4. Document the remediation process\n"
        guidance += "5. Verify the fix with a follow-up scan\n"
        
        if finding.cve_id:
            guidance += f"\n**Additional Information:**\n"
            guidance += f"- CVE Details: https://nvd.nist.gov/vuln/detail/{finding.cve_id}\n"
        
        return guidance
    
    async def apply_remediation_to_findings(self, scan_id: str):
        """Apply remediation guidance to all findings in a scan"""
        result = await self.db.execute(
            select(Finding).where(Finding.source_scan_id == scan_id)
        )
        findings = result.scalars().all()
        
        updated_count = 0
        for finding in findings:
            if not finding.remediation_guidance:
                guidance = await self.get_remediation_for_finding(finding)
                if guidance:
                    finding.remediation_guidance = guidance
                    
                    # Estimate effort based on severity and complexity
                    finding.effort_hours = self._estimate_effort(finding)
                    updated_count += 1
        
        await self.db.commit()
        logger.info(f"Applied remediation guidance to {updated_count} findings")
        
        return updated_count
    
    def _estimate_effort(self, finding: Finding) -> int:
        """Estimate remediation effort in hours based on various factors"""
        base_effort = {
            'CRITICAL': 8,
            'HIGH': 6,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        
        effort = base_effort.get(finding.severity, 4)
        
        # Adjust based on vulnerability type
        title_lower = (finding.title or '').lower()
        
        if 'configuration' in title_lower or 'misconfiguration' in title_lower:
            effort = max(1, effort - 2)  # Config changes are usually faster
        elif 'code' in title_lower or 'injection' in title_lower:
            effort += 4  # Code changes take longer
        elif 'patch' in title_lower or 'update' in title_lower:
            effort += 2  # Patching requires testing
        
        return max(1, min(effort, 40))  # Cap between 1 and 40 hours