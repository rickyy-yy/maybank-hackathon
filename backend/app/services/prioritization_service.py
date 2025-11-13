from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import logging
from datetime import datetime

from app.models.finding import Finding

logger = logging.getLogger(__name__)

class PrioritizationService:
    """
    Advanced prioritization service with multi-factor risk scoring
    
    Risk factors:
    1. CVSS Score (40% weight) - Technical severity
    2. Exploit Availability (25% weight) - Real-world threat
    3. Asset Criticality (20% weight) - Business impact
    4. Age of Vulnerability (15% weight) - Time-based urgency
    """
    
    # Default weights (sum to 1.0)
    DEFAULT_WEIGHTS = {
        'cvss': 0.40,
        'exploit': 0.25,
        'asset_criticality': 0.20,
        'age': 0.15
    }
    
    # Severity to numeric score mapping
    SEVERITY_SCORES = {
        'CRITICAL': 10.0,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 2.5,
        'INFO': 1.0
    }
    
    # Category to compliance impact mapping
    COMPLIANCE_CATEGORIES = {
        'sql_injection': 15,
        'xss': 12,
        'authentication': 15,
        'default_credentials': 15,
        'ssl_tls': 12,
        'password': 10,
        'information_disclosure': 10,
        'misconfiguration': 8,
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def prioritize_scan_findings(
        self,
        scan_id: str,
        weights: Optional[Dict] = None
    ) -> Dict:
        """
        Calculate priority scores for all findings in a scan
        
        Args:
            scan_id: UUID of the scan
            weights: Optional custom weights for risk factors
            
        Returns:
            Statistics about prioritization
        """
        weights = weights or self.DEFAULT_WEIGHTS
        
        # Get all findings for this scan
        result = await self.db.execute(
            select(Finding).where(Finding.source_scan_id == scan_id)
        )
        findings = result.scalars().all()
        
        if not findings:
            logger.warning(f"No findings found for scan {scan_id}")
            return {
                'total_findings': 0,
                'prioritized': 0
            }
        
        logger.info(f"Prioritizing {len(findings)} findings for scan {scan_id}")
        
        # Calculate risk scores
        scored_findings = []
        for finding in findings:
            score = self._calculate_risk_score(finding, weights)
            scored_findings.append({
                'id': finding.id,
                'score': score,
                'finding': finding
            })
        
        # Sort by score (highest first)
        scored_findings.sort(key=lambda x: x['score'], reverse=True)
        
        # Assign priority ranks and update findings
        for rank, item in enumerate(scored_findings, start=1):
            await self.db.execute(
                update(Finding)
                .where(Finding.id == item['id'])
                .values(
                    risk_score=item['score'],
                    priority_rank=rank
                )
            )
        
        await self.db.commit()
        
        logger.info(f"Successfully prioritized {len(findings)} findings")
        
        # Calculate statistics
        total_score = sum(item['score'] for item in scored_findings)
        avg_score = total_score / len(scored_findings) if scored_findings else 0
        
        return {
            'total_findings': len(findings),
            'prioritized': len(scored_findings),
            'average_score': round(avg_score, 2),
            'highest_score': scored_findings[0]['score'] if scored_findings else 0,
            'lowest_score': scored_findings[-1]['score'] if scored_findings else 0
        }
    
    def _calculate_risk_score(self, finding: Finding, weights: Dict) -> int:
        """
        Calculate comprehensive risk score (0-100)
        
        Formula:
        Risk = (CVSS_Component * W1) + (Exploit_Component * W2) + 
               (Asset_Component * W3) + (Age_Component * W4)
        """
        
        # Component 1: CVSS Score (0-40 points)
        cvss_component = self._calculate_cvss_component(finding) * weights['cvss']
        
        # Component 2: Exploit Availability (0-25 points)
        exploit_component = self._calculate_exploit_component(finding) * weights['exploit']
        
        # Component 3: Asset Criticality (0-20 points)
        asset_component = self._calculate_asset_component(finding) * weights['asset_criticality']
        
        # Component 4: Vulnerability Age (0-15 points)
        age_component = self._calculate_age_component(finding) * weights['age']
        
        # Sum all components
        total_score = (
            cvss_component +
            exploit_component +
            asset_component +
            age_component
        )
        
        # Normalize to 0-100 scale
        normalized_score = min(int(total_score), 100)
        
        logger.debug(
            f"Finding {finding.id}: CVSS={cvss_component:.1f}, "
            f"Exploit={exploit_component:.1f}, Asset={asset_component:.1f}, "
            f"Age={age_component:.1f}, Total={normalized_score}"
        )
        
        return normalized_score
    
    def _calculate_cvss_component(self, finding: Finding) -> float:
        """
        Calculate CVSS-based component (0-40 points)
        
        Uses actual CVSS score if available, otherwise maps from severity
        """
        if finding.cvss_score and finding.cvss_score > 0:
            # CVSS is 0-10 scale, convert to 0-40
            return (finding.cvss_score / 10.0) * 40.0
        
        # Fall back to severity-based scoring
        severity_score = self.SEVERITY_SCORES.get(finding.severity, 1.0)
        return (severity_score / 10.0) * 40.0
    
    def _calculate_exploit_component(self, finding: Finding) -> float:
        """
        Calculate exploit availability component (0-25 points)
        
        Factors:
        - Public exploit available: +25 points
        - CVE exists (known vulnerability): +15 points
        - Recent vulnerability (< 1 year): +10 points
        - No exploit info: +5 points (default)
        """
        # Check for direct exploit availability from Nessus
        evidence = finding.evidence or ''
        description = finding.description or ''
        
        # High score if exploit explicitly mentioned
        if any(keyword in evidence.lower() or keyword in description.lower() 
               for keyword in ['exploit', 'metasploit', 'poc', 'proof of concept']):
            return 25.0
        
        # Medium-high score if CVE exists (publicly disclosed)
        if finding.cve_id:
            return 20.0
        
        # Medium score for known vulnerability categories
        if finding.title and any(keyword in finding.title.lower() 
                                 for keyword in ['remote code execution', 'rce', 'injection', 'overflow']):
            return 15.0
        
        # Default score
        return 8.0
    
    def _calculate_asset_component(self, finding: Finding) -> float:
        """
        Calculate asset criticality component (0-20 points)
        
        Determines criticality from:
        - Hostname patterns (prod, staging, dev)
        - Service type (database, web, authentication)
        - Port numbers (common critical services)
        """
        score = 10.0  # Base score
        
        hostname = (finding.asset_hostname or finding.affected_asset or '').lower()
        service = (finding.service or '').lower()
        port = finding.port
        
        # Production environment detection
        if any(keyword in hostname for keyword in ['prod', 'production', 'prd', 'live']):
            score += 10.0
        elif any(keyword in hostname for keyword in ['stg', 'staging', 'stage', 'uat']):
            score += 5.0
        elif any(keyword in hostname for keyword in ['dev', 'development', 'test', 'qa']):
            score += 2.0
        
        # Critical service detection
        critical_services = ['database', 'db', 'sql', 'auth', 'ldap', 'ad', 'dc']
        if any(svc in service for svc in critical_services):
            score += 5.0
        
        # Critical port detection
        critical_ports = {
            3306: 'mysql',    # MySQL
            5432: 'postgresql',  # PostgreSQL
            1521: 'oracle',   # Oracle
            1433: 'mssql',    # MS SQL
            389: 'ldap',      # LDAP
            636: 'ldaps',     # LDAPS
            3389: 'rdp',      # RDP
            22: 'ssh',        # SSH
        }
        
        if port and port in critical_ports:
            score += 3.0
        
        return min(score, 20.0)
    
    def _calculate_age_component(self, finding: Finding) -> float:
        """
        Calculate vulnerability age component (0-15 points)
        
        Older vulnerabilities that haven't been fixed get higher urgency scores
        """
        if not finding.detected_date:
            return 7.5  # Default medium score
        
        # Calculate days since detection
        days_old = (datetime.utcnow() - finding.detected_date).days
        
        if days_old > 90:  # > 3 months
            return 15.0
        elif days_old > 60:  # > 2 months
            return 12.0
        elif days_old > 30:  # > 1 month
            return 9.0
        elif days_old > 7:  # > 1 week
            return 6.0
        else:  # < 1 week
            return 3.0