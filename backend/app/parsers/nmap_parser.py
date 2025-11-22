import xml.etree.ElementTree as ET
import csv
import re
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class NmapParser:
    """Parse Nmap XML and CSV scan reports"""

    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO',
        'informational': 'INFO'
    }

    def validate(self, file_content: bytes, file_extension: str) -> bool:
        """Validate if file is proper Nmap format"""
        try:
            if file_extension == '.xml':
                root = ET.fromstring(file_content)
                return root.tag == 'nmaprun'
            elif file_extension == '.csv':
                # Try to decode and check for Nmap-like headers
                content = file_content.decode('utf-8')
                return 'host' in content.lower() and 'port' in content.lower()
            return False
        except Exception as e:
            logger.error(f"Nmap validation error: {e}")
            return False

    def parse(self, file_content: bytes, file_extension: str) -> Dict:
        """Parse Nmap file and extract findings"""
        if file_extension == '.xml':
            return self._parse_xml(file_content)
        elif file_extension == '.csv':
            return self._parse_csv(file_content)
        else:
            raise ValueError(f"Unsupported Nmap file format: {file_extension}")

    def _parse_xml(self, file_content: bytes) -> Dict:
        """Parse Nmap XML format"""
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")

        scan_metadata = {
            'name': f"Nmap Scan - {root.get('startstr', 'Unknown')}",
            'scanner': root.get('scanner', 'nmap'),
            'version': root.get('version', 'unknown'),
            'start_time': root.get('start'),
        }

        findings = []
        hosts = root.findall('.//host')

        logger.info(f"Found {len(hosts)} hosts in Nmap scan")

        for host in hosts:
            host_data = self._extract_host_data(host)
            
            # Get all ports
            ports = host.findall('.//port')
            for port in ports:
                finding = self._parse_port(port, host_data)
                if finding:
                    findings.append(finding)

            # Get host scripts (OS detection, vulnerabilities, etc.)
            host_scripts = host.findall('.//hostscript/script')
            for script in host_scripts:
                finding = self._parse_script(script, host_data, None)
                if finding:
                    findings.append(finding)

        statistics = self._calculate_statistics(findings)

        return {
            'scan_name': scan_metadata['name'],
            'scan_date': datetime.utcnow(),
            'total_findings': len(findings),
            'findings': findings,
            'statistics': statistics,
            'metadata': scan_metadata
        }

    def _parse_csv(self, file_content: bytes) -> Dict:
        """Parse Nmap CSV format"""
        content = file_content.decode('utf-8')
        lines = content.strip().split('\n')
        
        if len(lines) < 2:
            raise ValueError("CSV file is empty or invalid")

        # Parse CSV
        reader = csv.DictReader(lines)
        findings = []

        for row in reader:
            finding = self._parse_csv_row(row)
            if finding:
                findings.append(finding)

        statistics = self._calculate_statistics(findings)

        return {
            'scan_name': 'Nmap CSV Scan',
            'scan_date': datetime.utcnow(),
            'total_findings': len(findings),
            'findings': findings,
            'statistics': statistics,
            'metadata': {'scanner': 'nmap', 'format': 'csv'}
        }

    def _extract_host_data(self, host: ET.Element) -> Dict:
        """Extract host information from XML"""
        host_data = {}

        # Get IP address
        address = host.find('.//address[@addrtype="ipv4"]')
        if address is None:
            address = host.find('.//address[@addrtype="ipv6"]')
        host_data['ip'] = address.get('addr') if address is not None else 'unknown'

        # Get hostname
        hostname = host.find('.//hostname')
        host_data['hostname'] = hostname.get('name') if hostname is not None else host_data['ip']

        # Get OS
        os_match = host.find('.//osmatch')
        host_data['os'] = os_match.get('name') if os_match is not None else 'Unknown'

        # Get status
        status = host.find('.//status')
        host_data['status'] = status.get('state') if status is not None else 'unknown'

        return host_data

    def _parse_port(self, port: ET.Element, host_data: Dict) -> Optional[Dict]:
        """Parse port information"""
        port_id = port.get('portid')
        protocol = port.get('protocol', 'tcp')

        state = port.find('.//state')
        if state is None or state.get('state') != 'open':
            return None  # Skip closed ports

        service = port.find('.//service')
        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
        service_product = service.get('product', '') if service is not None else ''
        service_version = service.get('version', '') if service is not None else ''

        # Build service string
        service_info = service_name
        if service_product:
            service_info += f" ({service_product}"
            if service_version:
                service_info += f" {service_version}"
            service_info += ")"

        # Check for vulnerabilities in scripts
        scripts = port.findall('.//script')
        if scripts:
            for script in scripts:
                vuln_finding = self._parse_script(script, host_data, port_id, protocol, service_info)
                if vuln_finding:
                    return vuln_finding

        # If no vulnerabilities, create an informational finding
        finding = {
            'plugin_id': f"nmap-port-{port_id}",
            'title': f"Open Port: {port_id}/{protocol} - {service_name}",
            'description': f"Port {port_id}/{protocol} is open and running {service_info}",
            'severity': 'INFO',
            'affected_host': host_data['hostname'],
            'port': port_id,
            'protocol': protocol,
            'service': service_info,
            'host_properties': host_data,
            'cvss_score': None,
            'cve_id': None,
            'cwe_id': None,
            'evidence': None
        }

        return finding

    def _parse_script(self, script: ET.Element, host_data: Dict, port: Optional[str] = None, 
                     protocol: str = 'tcp', service: str = 'unknown') -> Optional[Dict]:
        """Parse Nmap script output for vulnerabilities"""
        script_id = script.get('id', '')
        script_output = script.get('output', '')

        # Check if this is a vulnerability script
        if 'vuln' not in script_id and 'cve' not in script_id.lower():
            return None

        # Extract CVE if present
        cve_match = re.search(r'(CVE-\d{4}-\d+)', script_output, re.IGNORECASE)
        cve_id = cve_match.group(1) if cve_match else None

        # Determine severity from script output
        severity = self._determine_severity_from_output(script_output)

        # Extract CVSS score if present
        cvss_match = re.search(r'CVSS:\s*(\d+\.?\d*)', script_output, re.IGNORECASE)
        cvss_score = float(cvss_match.group(1)) if cvss_match else None

        finding = {
            'plugin_id': f"nmap-{script_id}",
            'title': f"Nmap Script Detection: {script_id}",
            'description': script_output[:500],  # Limit description length
            'severity': severity,
            'affected_host': host_data['hostname'],
            'port': port,
            'protocol': protocol,
            'service': service,
            'host_properties': host_data,
            'cvss_score': cvss_score,
            'cve_id': cve_id,
            'cwe_id': None,
            'evidence': script_output
        }

        return finding

    def _parse_csv_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single CSV row"""
        try:
            # Common CSV column names (case-insensitive matching)
            host = row.get('host') or row.get('Host') or row.get('IP') or row.get('ip', 'unknown')
            port = row.get('port') or row.get('Port') or row.get('PORT')
            protocol = row.get('protocol') or row.get('Protocol') or row.get('proto', 'tcp')
            service = row.get('service') or row.get('Service') or row.get('name', 'unknown')
            state = row.get('state') or row.get('State') or row.get('status', 'open')

            if state.lower() != 'open':
                return None

            finding = {
                'plugin_id': f"nmap-csv-{port}",
                'title': f"Open Port: {port}/{protocol} - {service}",
                'description': f"Port {port}/{protocol} is open and running {service}",
                'severity': 'INFO',
                'affected_host': host,
                'port': int(port) if port and port.isdigit() else None,
                'protocol': protocol,
                'service': service,
                'host_properties': {'ip': host},
                'cvss_score': None,
                'cve_id': None,
                'cwe_id': None,
                'evidence': None
            }

            return finding

        except Exception as e:
            logger.error(f"Error parsing CSV row: {e}")
            return None

    def _determine_severity_from_output(self, output: str) -> str:
        """Determine severity from script output"""
        output_lower = output.lower()

        if any(word in output_lower for word in ['critical', 'severe', 'dangerous']):
            return 'CRITICAL'
        elif any(word in output_lower for word in ['high', 'important', 'major']):
            return 'HIGH'
        elif any(word in output_lower for word in ['medium', 'moderate', 'warning']):
            return 'MEDIUM'
        elif any(word in output_lower for word in ['low', 'minor']):
            return 'LOW'
        else:
            return 'INFO'

    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """Calculate statistics from findings"""
        stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
            'total': len(findings),
            'unique_hosts': set()
        }

        for finding in findings:
            severity = finding.get('severity', 'INFO')
            stats[severity] = stats.get(severity, 0) + 1
            
            host = finding.get('affected_host')
            if host:
                stats['unique_hosts'].add(host)

        stats['unique_hosts'] = len(stats['unique_hosts'])
        return stats