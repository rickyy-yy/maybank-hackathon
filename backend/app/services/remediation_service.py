from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, Dict, List
import logging
import httpx
import os

from app.models.finding import Finding
from app.models.template import RemediationTemplate

logger = logging.getLogger(__name__)


class RemediationService:
    """Service for matching findings to remediation guidance with web search enhancement"""

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
        self.web_search_enabled = bool(os.getenv('ENABLE_WEB_SEARCH', 'false').lower() == 'true')

    async def get_remediation_for_finding(self, finding: Finding) -> Optional[str]:
        """
        Get comprehensive remediation guidance for a specific finding
        Combines template-based guidance with real-time web search results

        Args:
            finding: Finding object

        Returns:
            Enhanced remediation guidance text or None
        """
        remediation_parts = []

        # Try to match by CWE first
        if finding.cwe_id:
            remediation = await self._get_remediation_by_cwe(finding.cwe_id)
            if remediation:
                remediation_parts.append(remediation)

        # Try to match by plugin name pattern
        if finding.title and not remediation_parts:
            remediation = await self._get_remediation_by_pattern(finding.title)
            if remediation:
                remediation_parts.append(remediation)

        # If no template found, use generic remediation
        if not remediation_parts:
            remediation_parts.append(self._get_generic_remediation(finding))

        # Enhance with web search if enabled and vulnerability is critical/high
        if self.web_search_enabled and finding.severity in ['CRITICAL', 'HIGH']:
            web_guidance = await self._get_web_search_guidance(finding)
            if web_guidance:
                remediation_parts.append("\n\n---\n\n## 🔍 Latest Security Advisories & Solutions\n\n" + web_guidance)

        return '\n'.join(remediation_parts)

    async def _get_web_search_guidance(self, finding: Finding) -> Optional[str]:
        """
        Search the web for latest security advisories and remediation guidance

        Args:
            finding: Finding object with vulnerability details

        Returns:
            Formatted web search results or None
        """
        try:
            # Build search query based on available information
            search_terms = []

            if finding.cve_id:
                search_terms.append(f"{finding.cve_id} remediation fix")
            elif finding.cwe_id:
                search_terms.append(f"{finding.cwe_id} fix")

            # Add vulnerability title
            if finding.title:
                # Clean up the title for better search results
                clean_title = finding.title.replace('[', '').replace(']', '').strip()
                search_terms.append(f"{clean_title} vulnerability fix 2024")

            if not search_terms:
                return None

            # Use the primary search query
            query = search_terms[0]

            logger.info(f"Searching web for guidance: {query}")

            # Simulate web search results (in production, integrate with actual search API)
            # You would call your backend's web search endpoint here
            async with httpx.AsyncClient(timeout=10.0) as client:
                try:
                    # This would be your actual API call to search service
                    # For now, we'll structure it to show how it would work
                    guidance = await self._format_search_results(finding, query)
                    return guidance
                except Exception as e:
                    logger.error(f"Web search error: {e}")
                    return None

        except Exception as e:
            logger.error(f"Error getting web search guidance: {e}")
            return None

    async def _format_search_results(self, finding: Finding, query: str) -> str:
        """Format web search results into actionable guidance"""

        guidance_parts = []

        # Add search context
        guidance_parts.append(f"**Search Query:** {query}\n")

        # Add CVE/CWE specific resources
        if finding.cve_id:
            guidance_parts.append(
                f"### Official CVE Information\n"
                f"- **NVD Database:** https://nvd.nist.gov/vuln/detail/{finding.cve_id}\n"
                f"- **MITRE CVE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name={finding.cve_id}\n"
            )

        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace('CWE-', '')
            guidance_parts.append(
                f"### CWE Reference\n"
                f"- **MITRE CWE:** https://cwe.mitre.org/data/definitions/{cwe_num}.html\n"
            )

        # Add vendor-specific guidance
        guidance_parts.append(
            f"\n### Recommended Actions\n"
            f"1. **Check Vendor Advisories:** Review security bulletins from your software vendor\n"
            f"2. **Apply Latest Patches:** Ensure all security updates are applied\n"
            f"3. **Review Configuration:** Verify security settings against best practices\n"
            f"4. **Test in Staging:** Validate fixes in non-production environment first\n"
            f"5. **Monitor for Exploits:** Check if active exploits exist in the wild\n"
        )

        # Add OWASP resources for common web vulnerabilities
        if any(keyword in finding.title.lower() for keyword in ['injection', 'xss', 'csrf', 'authentication']):
            guidance_parts.append(
                f"\n### OWASP Resources\n"
                f"- **OWASP Top 10:** https://owasp.org/www-project-top-ten/\n"
                f"- **Cheat Sheets:** https://cheatsheetseries.owasp.org/\n"
            )

        return '\n'.join(guidance_parts)

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

    def _format_remediation(self, template: RemediationTemplate) -> str:
        """Format remediation template into guidance text"""
        parts = []

        parts.append(f"# {template.title}\n")

        if template.description:
            parts.append(f"## Overview\n{template.description}\n")

        if template.remediation_steps:
            parts.append(f"## Remediation Steps\n{template.remediation_steps}\n")

        if template.code_examples:
            parts.append(f"## Code Examples\n```\n{template.code_examples}\n```\n")

        if template.effort_hours:
            parts.append(f"**⏱️ Estimated Effort:** {template.effort_hours} hours\n")

        if template.required_skills:
            skills = ', '.join(template.required_skills)
            parts.append(f"**👥 Required Skills:** {skills}\n")

        if template.references:
            refs = '\n'.join([f"- {ref}" for ref in template.references])
            parts.append(f"## References\n{refs}\n")

        return '\n'.join(parts)

    def _get_generic_remediation(self, finding: Finding) -> str:
        """Generate generic remediation guidance based on severity and description"""
        severity = finding.severity

        parts = []
        parts.append(f"# Generic Remediation Guidance\n")
        parts.append(f"**Severity:** {severity}\n")

        if severity == 'CRITICAL':
            parts.append(
                "\n⚠️ **URGENT:** Immediate action required. This vulnerability poses a critical risk to your systems.\n")
            parts.append("**Timeline:** Fix within 24 hours\n")
        elif severity == 'HIGH':
            parts.append("\n🔴 **High Priority:** Address this vulnerability as soon as possible.\n")
            parts.append("**Timeline:** Fix within 7 days\n")
        elif severity == 'MEDIUM':
            parts.append("\n🟡 **Medium Priority:** Schedule remediation in your next sprint.\n")
            parts.append("**Timeline:** Fix within 30 days\n")
        else:
            parts.append("\n🔵 **Low Priority:** Address during regular maintenance.\n")
            parts.append("**Timeline:** Fix within 90 days\n")

        parts.append("\n## Recommended Actions\n")
        parts.append("1. **Assess Impact:** Review the vulnerability description and evidence\n")
        parts.append("2. **Research Solution:** Consult vendor advisories and security bulletins\n")
        parts.append("3. **Test Fix:** Validate remediation in non-production environment\n")
        parts.append("4. **Apply Fix:** Deploy to production with change management process\n")
        parts.append("5. **Verify:** Conduct follow-up scan to confirm remediation\n")
        parts.append("6. **Document:** Record the issue and resolution for audit trail\n")

        if finding.cve_id:
            parts.append(f"\n## Additional Resources\n")
            parts.append(f"- **CVE Details:** https://nvd.nist.gov/vuln/detail/{finding.cve_id}\n")
            parts.append(f"- **Exploit Database:** https://www.exploit-db.com/search?cve={finding.cve_id}\n")

        return '\n'.join(parts)

    async def apply_remediation_to_findings(self, scan_id: str) -> int:
        """Apply remediation guidance to all findings in a scan"""
        result = await self.db.execute(
            select(Finding).where(Finding.source_scan_id == scan_id)
        )
        findings = result.scalars().all()

        updated_count = 0
        for finding in findings:
            if not finding.remediation_guidance:
                try:
                    guidance = await self.get_remediation_for_finding(finding)
                    if guidance:
                        finding.remediation_guidance = guidance
                        finding.effort_hours = self._estimate_effort(finding)
                        updated_count += 1
                except Exception as e:
                    logger.error(f"Error applying remediation to finding {finding.id}: {e}")
                    continue

        await self.db.commit()
        logger.info(f"Applied remediation guidance to {updated_count}/{len(findings)} findings")

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