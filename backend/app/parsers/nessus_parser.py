import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from datetime import datetime
import re
from app.parsers.base_parser import BaseParser

class NessusParser(BaseParser):
    """Parse Nessus XML scan reports"""
    
    SEVERITY_MAP = {
        '0': 'INFO',
        '1': 'LOW',
        '2': 'MEDIUM',
        '3': 'HIGH',
        '4': 'CRITICAL'
    }
    
    def validate(self, file_content: bytes) -> bool:
        """Check if file is valid Nessus XML"""
        try:
            root = ET.fromstring(file_content)
            return root.tag == 'NessusClientData_v2'
        except ET.ParseError:
            return False
    
    def parse(self, file_content: bytes) -> Dict:
        """
        Parse Nessus XML file and return normalized findings
        
        Args:
            file_content: Raw XML file bytes
            
        Returns:
            Dictionary containing scan metadata and findings
        """
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")
        
        # Extract scan metadata
        policy = root.find('.//Policy')
        scan_name = 'Unknown'
        if policy is not None:
            policy_name = policy.find('policyName')
            if policy_name is not None and policy_name.text:
                scan_name = policy_name.text
        
        # Extract all findings
        findings = []
        for report in root.findall('.//Report'):
            report_host = report.get('name', 'unknown')
            
            for item in report.findall('.//ReportItem'):
                finding = self._parse_report_item(item, report_host)
                if finding:
                    findings.append(finding)
        
        statistics = self._calculate_statistics(findings)
        
        return {
            'scan_name': scan_name,
            'scan_date': datetime.utcnow(),
            'total_findings': len(findings),
            'findings': findings,
            'statistics': statistics
        }
    
    def _parse_report_item(self, item: ET.Element, host: str) -> Optional[Dict]:
        """Parse individual ReportItem element"""
        
        plugin_id = item.get('pluginID', '')
        severity = self.SEVERITY_MAP.get(item.get('severity', '0'), 'INFO')
        
        # Skip informational findings for MVP
        if severity == 'INFO':
            return None
        
        # Extract basic fields
        finding = {
            'plugin_id': plugin_id,
            'plugin_name': item.get('pluginName', 'Unknown'),
            'severity': severity,
            'affected_host': host,
            'port': item.get('port'),
            'protocol': item.get('protocol'),
            'service': item.get('svc_name', 'unknown'),
        }
        
        # Extract detailed information from child elements
        cve_ids = []
        references = []
        
        for child in item:
            if child.tag == 'description':
                finding['description'] = child.text or ''
            elif child.tag == 'solution':
                finding['solution'] = child.text or ''
            elif child.tag == 'synopsis':
                finding['synopsis'] = child.text or ''
            elif child.tag == 'plugin_output':
                finding['evidence'] = child.text or ''
            elif child.tag == 'risk_factor':
                finding['risk_factor'] = child.text or ''
            elif child.tag == 'cvss_base_score':
                try:
                    finding['cvss_score'] = float(child.text) if child.text else None
                except (ValueError, TypeError):
                    finding['cvss_score'] = None
            elif child.tag == 'cvss_vector':
                finding['cvss_vector'] = child.text or ''
            elif child.tag == 'cvss3_base_score':
                try:
                    # Prefer CVSS v3 if available
                    cvss3_score = float(child.text) if child.text else None
                    if cvss3_score:
                        finding['cvss_score'] = cvss3_score
                except (ValueError, TypeError):
                    pass
            elif child.tag == 'cvss3_vector':
                finding['cvss_vector'] = child.text or ''
            elif child.tag == 'cve':
                if child.text:
                    cve_ids.append(child.text)
            elif child.tag == 'xref':
                if child.text:
                    references.append(child.text)
        
        # Store CVE IDs
        if cve_ids:
            finding['cve_ids'] = cve_ids
            finding['cve_id'] = cve_ids[0]  # Use first CVE as primary
        
        # Store references
        if references:
            finding['references'] = references
        
        # Extract CWE if present
        finding['cwe_id'] = self._extract_cwe(finding)
        
        # Create title from plugin name or synopsis
        finding['title'] = finding.get('synopsis', finding['plugin_name'])
        
        return finding
    
    def _extract_cwe(self, finding: Dict) -> Optional[str]:
        """Extract CWE identifier from finding data"""
        cwe_pattern = r'CWE-(\d+)'
        
        # Check description
        description = finding.get('description', '')
        if description:
            match = re.search(cwe_pattern, description)
            if match:
                return f"CWE-{match.group(1)}"
        
        # Check references
        references = finding.get('references', [])
        for ref in references:
            if 'CWE' in ref:
                match = re.search(cwe_pattern, ref)
                if match:
                    return f"CWE-{match.group(1)}"
        
        return None
    
    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """Calculate finding statistics by severity"""
        stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            stats[severity] = stats.get(severity, 0) + 1
        
        return stats