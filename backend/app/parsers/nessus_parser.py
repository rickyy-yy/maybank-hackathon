import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)


class NessusParser:
    """Parse Nessus XML scan reports with comprehensive data extraction"""

    # Nessus severity to standard severity mapping
    SEVERITY_MAP = {
        '0': 'INFO',
        '1': 'LOW',
        '2': 'MEDIUM',
        '3': 'HIGH',
        '4': 'CRITICAL'
    }

    # Plugin families that indicate specific vulnerability types
    PLUGIN_FAMILIES = {
        'Web Servers': 'web_server',
        'CGI abuses': 'web_application',
        'Databases': 'database',
        'Windows': 'windows',
        'Unix': 'unix',
        'Service detection': 'service',
        'General': 'general',
    }

    def validate(self, file_content: bytes) -> bool:
        """Validate if file is proper Nessus XML format"""
        try:
            root = ET.fromstring(file_content)
            # Check for NessusClientData_v2 root element
            if root.tag not in ['NessusClientData_v2', 'NessusClientData']:
                return False
            # Verify it has at least one Report element
            reports = root.findall('.//Report')
            return len(reports) > 0
        except ET.ParseError as e:
            logger.error(f"XML parse error during validation: {e}")
            return False
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False

    def parse(self, file_content: bytes) -> Dict:
        """
        Parse Nessus XML file and extract all vulnerability data

        Args:
            file_content: Raw XML file bytes

        Returns:
            Dictionary with scan metadata, findings, and statistics
        """
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")

        # Extract scan metadata
        scan_metadata = self._extract_scan_metadata(root)

        # Extract all findings from all hosts
        all_findings = []
        report_hosts = root.findall('.//ReportHost')

        logger.info(f"Found {len(report_hosts)} hosts in scan")

        for report_host in report_hosts:
            host_name = report_host.get('name', 'unknown')
            host_properties = self._extract_host_properties(report_host)

            # Get all ReportItems (vulnerabilities) for this host
            report_items = report_host.findall('.//ReportItem')
            logger.info(f"Processing {len(report_items)} items for host {host_name}")

            for item in report_items:
                finding = self._parse_report_item(item, host_name, host_properties)
                if finding:
                    all_findings.append(finding)

        # Calculate statistics
        statistics = self._calculate_statistics(all_findings)

        logger.info(f"Parsed {len(all_findings)} total findings")

        return {
            'scan_name': scan_metadata.get('name', 'Unknown Scan'),
            'scan_date': datetime.utcnow(),
            'total_findings': len(all_findings),
            'findings': all_findings,
            'statistics': statistics,
            'metadata': scan_metadata
        }

    def _extract_scan_metadata(self, root: ET.Element) -> Dict:
        """Extract scan-level metadata"""
        metadata = {
            'name': 'Unknown Scan',
            'policy': None,
            'scan_start': None,
            'scan_end': None
        }

        # Try to get policy name
        policy = root.find('.//Policy/policyName')
        if policy is not None and policy.text:
            metadata['name'] = policy.text
            metadata['policy'] = policy.text

        # Try to get report name as fallback
        report = root.find('.//Report')
        if report is not None:
            report_name = report.get('name')
            if report_name and metadata['name'] == 'Unknown Scan':
                metadata['name'] = report_name

        return metadata

    def _extract_host_properties(self, report_host: ET.Element) -> Dict:
        """Extract host-specific properties"""
        properties = {}

        # Extract host properties
        host_props = report_host.find('.//HostProperties')
        if host_props is not None:
            for tag in host_props.findall('tag'):
                name = tag.get('name', '')
                value = tag.text or ''

                # Store useful properties
                if name == 'host-ip':
                    properties['ip'] = value
                elif name == 'host-fqdn':
                    properties['fqdn'] = value
                elif name == 'operating-system':
                    properties['os'] = value
                elif name == 'system-type':
                    properties['system_type'] = value
                elif name == 'host-rdns':
                    properties['rdns'] = value

        return properties

    def _parse_report_item(self, item: ET.Element, host: str, host_properties: Dict) -> Optional[Dict]:
        """Parse individual vulnerability from ReportItem"""

        # Extract basic attributes
        plugin_id = item.get('pluginID', '')
        plugin_name = item.get('pluginName', 'Unknown')
        port = item.get('port', '0')
        protocol = item.get('protocol', 'tcp')
        service = item.get('svc_name', 'unknown')
        severity_code = item.get('severity', '0')
        plugin_family = item.get('pluginFamily', 'General')

        # Map severity
        severity = self.SEVERITY_MAP.get(severity_code, 'INFO')

        # Skip purely informational items unless they're important
        if severity == 'INFO' and not self._is_important_info(plugin_id, plugin_name):
            return None

        # Initialize finding dictionary
        finding = {
            'plugin_id': plugin_id,
            'plugin_name': plugin_name,
            'plugin_family': plugin_family,
            'severity': severity,
            'affected_host': host,
            'port': port,
            'protocol': protocol,
            'service': service,
            'host_properties': host_properties
        }

        # Extract all child elements
        description = None
        solution = None
        synopsis = None
        plugin_output = None
        risk_factor = None
        cvss_base = None
        cvss3_base = None
        cvss_vector = None
        cvss3_vector = None
        cve_list = []
        references = []
        see_also = []
        exploit_available = False
        vuln_publication_date = None
        patch_publication_date = None

        for child in item:
            text = child.text or ''

            if child.tag == 'description':
                description = text.strip()
            elif child.tag == 'solution':
                solution = text.strip()
            elif child.tag == 'synopsis':
                synopsis = text.strip()
            elif child.tag == 'plugin_output':
                plugin_output = text.strip()
            elif child.tag == 'risk_factor':
                risk_factor = text.strip()
            elif child.tag == 'cvss_base_score':
                try:
                    cvss_base = float(text) if text else None
                except (ValueError, TypeError):
                    pass
            elif child.tag == 'cvss3_base_score':
                try:
                    cvss3_base = float(text) if text else None
                except (ValueError, TypeError):
                    pass
            elif child.tag == 'cvss_vector':
                cvss_vector = text.strip()
            elif child.tag == 'cvss3_vector':
                cvss3_vector = text.strip()
            elif child.tag == 'cve':
                if text.strip():
                    cve_list.append(text.strip())
            elif child.tag == 'xref':
                if text.strip():
                    references.append(text.strip())
            elif child.tag == 'see_also':
                if text.strip():
                    see_also.extend([url.strip() for url in text.split('\n') if url.strip()])
            elif child.tag == 'exploit_available':
                exploit_available = text.strip().lower() == 'true'
            elif child.tag == 'exploitability_ease':
                finding['exploitability_ease'] = text.strip()
            elif child.tag == 'vuln_publication_date':
                vuln_publication_date = text.strip()
            elif child.tag == 'patch_publication_date':
                patch_publication_date = text.strip()
            elif child.tag == 'cvss_temporal_score':
                try:
                    finding['cvss_temporal_score'] = float(text) if text else None
                except (ValueError, TypeError):
                    pass
            elif child.tag == 'plugin_modification_date':
                finding['plugin_modification_date'] = text.strip()
            elif child.tag == 'plugin_publication_date':
                finding['plugin_publication_date'] = text.strip()

        # Store extracted data
        finding['description'] = description or synopsis or plugin_name
        finding['solution'] = solution
        finding['synopsis'] = synopsis
        finding['evidence'] = plugin_output
        finding['risk_factor'] = risk_factor

        # Prefer CVSS v3 over v2
        if cvss3_base:
            finding['cvss_score'] = cvss3_base
            finding['cvss_vector'] = cvss3_vector
            finding['cvss_version'] = 3
        elif cvss_base:
            finding['cvss_score'] = cvss_base
            finding['cvss_vector'] = cvss_vector
            finding['cvss_version'] = 2
        else:
            finding['cvss_score'] = None
            finding['cvss_vector'] = None

        # Store CVE information
        if cve_list:
            finding['cve_ids'] = cve_list
            finding['cve_id'] = cve_list[0]  # Primary CVE

        # Store references
        finding['references'] = references
        finding['see_also'] = see_also

        # Exploit information
        finding['exploit_available'] = exploit_available
        finding['vuln_publication_date'] = vuln_publication_date
        finding['patch_publication_date'] = patch_publication_date

        # Extract CWE
        finding['cwe_id'] = self._extract_cwe(finding)

        # Create meaningful title
        finding['title'] = synopsis or plugin_name

        # Determine vulnerability category
        finding['category'] = self._categorize_vulnerability(finding)

        return finding

    def _is_important_info(self, plugin_id: str, plugin_name: str) -> bool:
        """Determine if an INFO-level finding is important enough to keep"""
        important_keywords = [
            'ssl', 'tls', 'certificate', 'cipher', 'encryption',
            'authentication', 'credential', 'password', 'security'
        ]

        plugin_name_lower = plugin_name.lower()
        return any(keyword in plugin_name_lower for keyword in important_keywords)

    def _extract_cwe(self, finding: Dict) -> Optional[str]:
        """Extract CWE identifier from finding data"""
        cwe_pattern = r'CWE-(\d+)'

        # Check description
        description = finding.get('description', '')
        if description:
            match = re.search(cwe_pattern, description, re.IGNORECASE)
            if match:
                return f"CWE-{match.group(1)}"

        # Check references
        references = finding.get('references', [])
        for ref in references:
            if 'CWE' in ref.upper():
                match = re.search(cwe_pattern, ref, re.IGNORECASE)
                if match:
                    return f"CWE-{match.group(1)}"

        # Check see_also URLs
        see_also = finding.get('see_also', [])
        for url in see_also:
            if 'cwe.mitre.org' in url.lower():
                match = re.search(cwe_pattern, url, re.IGNORECASE)
                if match:
                    return f"CWE-{match.group(1)}"

        return None

    def _categorize_vulnerability(self, finding: Dict) -> str:
        """Categorize vulnerability based on plugin family and name"""
        plugin_family = finding.get('plugin_family', '').lower()
        plugin_name = finding.get('plugin_name', '').lower()

        # Web application vulnerabilities
        if 'sql injection' in plugin_name or 'sqli' in plugin_name:
            return 'sql_injection'
        elif 'xss' in plugin_name or 'cross-site scripting' in plugin_name:
            return 'xss'
        elif 'csrf' in plugin_name or 'cross-site request forgery' in plugin_name:
            return 'csrf'
        elif 'cgi' in plugin_family or 'web' in plugin_family:
            return 'web_application'

        # Network vulnerabilities
        elif 'ssl' in plugin_name or 'tls' in plugin_name:
            return 'ssl_tls'
        elif 'ssh' in plugin_name:
            return 'ssh'
        elif 'rdp' in plugin_name:
            return 'rdp'
        elif 'smb' in plugin_name:
            return 'smb'

        # Authentication and access control
        elif 'authentication' in plugin_name or 'credential' in plugin_name:
            return 'authentication'
        elif 'password' in plugin_name:
            return 'password'
        elif 'default' in plugin_name and ('password' in plugin_name or 'credential' in plugin_name):
            return 'default_credentials'

        # Configuration issues
        elif 'misconfiguration' in plugin_name or 'configuration' in plugin_name:
            return 'misconfiguration'
        elif 'information disclosure' in plugin_name:
            return 'information_disclosure'

        # OS-specific
        elif 'windows' in plugin_family:
            return 'windows'
        elif 'unix' in plugin_family or 'linux' in plugin_name:
            return 'unix'

        # Database
        elif 'database' in plugin_family or 'mysql' in plugin_name or 'postgresql' in plugin_name:
            return 'database'

        return 'general'

    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """Calculate comprehensive statistics from findings"""
        stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
            'total': len(findings),
            'with_cvss': 0,
            'with_cve': 0,
            'with_exploit': 0,
            'unique_hosts': set(),
            'categories': {}
        }

        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'INFO')
            stats[severity] = stats.get(severity, 0) + 1

            # Count findings with CVSS scores
            if finding.get('cvss_score'):
                stats['with_cvss'] += 1

            # Count findings with CVE IDs
            if finding.get('cve_id'):
                stats['with_cve'] += 1

            # Count findings with exploits
            if finding.get('exploit_available'):
                stats['with_exploit'] += 1

            # Track unique hosts
            host = finding.get('affected_host')
            if host:
                stats['unique_hosts'].add(host)

            # Count by category
            category = finding.get('category', 'general')
            stats['categories'][category] = stats['categories'].get(category, 0) + 1

        # Convert set to count
        stats['unique_hosts'] = len(stats['unique_hosts'])

        return stats