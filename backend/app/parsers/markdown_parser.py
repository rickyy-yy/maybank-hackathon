import re
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class MarkdownParser:
    """Parse vulnerability reports in Markdown format"""

    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO',
        'informational': 'INFO'
    }

    def validate(self, file_content: bytes) -> bool:
        """Validate if file is Markdown format"""
        try:
            content = file_content.decode('utf-8')
            # Check for common markdown patterns
            return bool(re.search(r'#+\s+\w+', content))
        except Exception as e:
            logger.error(f"Markdown validation error: {e}")
            return False

    def parse(self, file_content: bytes) -> Dict:
        """Parse Markdown vulnerability report"""
        content = file_content.decode('utf-8')

        # Try different parsing strategies
        findings = []

        # Strategy 1: Parse structured vulnerability sections
        structured_findings = self._parse_structured_format(content)
        if structured_findings:
            findings.extend(structured_findings)

        # Strategy 2: Parse table format
        if not findings:
            table_findings = self._parse_table_format(content)
            if table_findings:
                findings.extend(table_findings)

        # Strategy 3: Parse simple list format
        if not findings:
            list_findings = self._parse_list_format(content)
            if list_findings:
                findings.extend(list_findings)

        if not findings:
            raise ValueError("No vulnerability findings found in Markdown file")

        statistics = self._calculate_statistics(findings)

        return {
            'scan_name': 'Markdown Vulnerability Report',
            'scan_date': datetime.utcnow(),
            'total_findings': len(findings),
            'findings': findings,
            'statistics': statistics,
            'metadata': {'scanner': 'markdown', 'format': 'md'}
        }

    def _parse_structured_format(self, content: str) -> List[Dict]:
        """Parse structured markdown with sections for each vulnerability"""
        findings = []

        # Split by H2 or H3 headers
        sections = re.split(r'\n#{2,3}\s+', content)

        for idx, section in enumerate(sections[1:], start=1):  # Skip first section (usually intro)
            lines = section.split('\n')
            title = lines[0].strip() if lines else f"Finding {idx}"

            finding = {
                'plugin_id': f"md-{idx}",
                'title': title,
                'description': '',
                'severity': 'INFO',
                'affected_host': 'unknown',
                'port': None,
                'protocol': None,
                'service': 'unknown',
                'host_properties': {},
                'cvss_score': None,
                'cve_id': None,
                'cwe_id': None,
                'evidence': None
            }

            # Parse section content
            for line in lines[1:]:
                line_lower = line.lower().strip()

                # Extract severity
                if 'severity' in line_lower or 'risk' in line_lower:
                    severity_match = re.search(r'(critical|high|medium|low|info)', line_lower)
                    if severity_match:
                        finding['severity'] = self.SEVERITY_MAP.get(severity_match.group(1), 'INFO')

                # Extract host/IP
                if 'host' in line_lower or 'target' in line_lower or 'ip' in line_lower:
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        finding['affected_host'] = ip_match.group(0)

                # Extract CVE
                cve_match = re.search(r'CVE-\d{4}-\d+', line, re.IGNORECASE)
                if cve_match:
                    finding['cve_id'] = cve_match.group(0).upper()

                # Extract CVSS
                cvss_match = re.search(r'CVSS:\s*(\d+\.?\d*)', line, re.IGNORECASE)
                if cvss_match:
                    finding['cvss_score'] = float(cvss_match.group(1))

                # Extract port
                port_match = re.search(r'port[:\s]+(\d+)', line_lower)
                if port_match:
                    finding['port'] = int(port_match.group(1))

                # Build description
                if line.strip() and not any(
                        keyword in line_lower for keyword in ['severity', 'host', 'port', 'cve', 'cvss']):
                    if finding['description']:
                        finding['description'] += '\n'
                    finding['description'] += line.strip()

            if finding['title']:
                findings.append(finding)

        return findings

    def _parse_table_format(self, content: str) -> List[Dict]:
        """Parse markdown table format"""
        findings = []

        # Find tables
        table_pattern = r'\|(.+\|.+)\n\|[-\s|]+\n((?:\|.+\n)+)'
        tables = re.findall(table_pattern, content)

        for table_header, table_body in tables:
            # Parse headers
            headers = [h.strip().lower() for h in table_header.split('|') if h.strip()]

            # Parse rows
            rows = [row for row in table_body.split('\n') if row.strip()]

            for idx, row in enumerate(rows, start=1):
                cells = [cell.strip() for cell in row.split('|') if cell.strip()]

                if len(cells) != len(headers):
                    continue

                row_dict = dict(zip(headers, cells))
                finding = self._parse_table_row(row_dict, idx)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_table_row(self, row: Dict, idx: int) -> Optional[Dict]:
        """Parse a table row into a finding"""
        title = row.get('vulnerability') or row.get('title') or row.get('name') or row.get('issue')
        if not title:
            return None

        severity = row.get('severity') or row.get('risk') or row.get('priority', 'info')
        host = row.get('host') or row.get('ip') or row.get('target', 'unknown')

        finding = {
            'plugin_id': f"md-table-{idx}",
            'title': title,
            'description': row.get('description') or row.get('details') or title,
            'severity': self.SEVERITY_MAP.get(severity.lower(), 'INFO'),
            'affected_host': host,
            'port': self._extract_port(row.get('port')),
            'protocol': row.get('protocol') or 'tcp',
            'service': row.get('service') or 'unknown',
            'host_properties': {'ip': host},
            'cvss_score': self._extract_cvss(row.get('cvss')),
            'cve_id': self._extract_cve(row.get('cve')),
            'cwe_id': None,
            'evidence': None
        }

        return finding

    def _parse_list_format(self, content: str) -> List[Dict]:
        """Parse simple bullet/numbered list format"""
        findings = []

        # Find list items
        list_items = re.findall(r'^[\s]*[-*\d.]+\s+(.+)$', content, re.MULTILINE)

        for idx, item in enumerate(list_items, start=1):
            # Try to extract severity from the item
            severity = 'INFO'
            severity_match = re.search(r'\[(critical|high|medium|low|info)\]', item, re.IGNORECASE)
            if severity_match:
                severity = self.SEVERITY_MAP.get(severity_match.group(1).lower(), 'INFO')

            # Extract CVE if present
            cve_match = re.search(r'CVE-\d{4}-\d+', item, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else None

            # Extract IP if present
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', item)
            host = ip_match.group(0) if ip_match else 'unknown'

            finding = {
                'plugin_id': f"md-list-{idx}",
                'title': item[:200],
                'description': item,
                'severity': severity,
                'affected_host': host,
                'port': None,
                'protocol': None,
                'service': 'unknown',
                'host_properties': {'ip': host} if ip_match else {},
                'cvss_score': None,
                'cve_id': cve_id,
                'cwe_id': None,
                'evidence': None
            }

            findings.append(finding)

        return findings

    def _extract_port(self, port_str: Optional[str]) -> Optional[int]:
        """Extract port number from string"""
        if not port_str:
            return None

        match = re.search(r'(\d+)', str(port_str))
        if match:
            return int(match.group(1))
        return None

    def _extract_cvss(self, cvss_str: Optional[str]) -> Optional[float]:
        """Extract CVSS score from string"""
        if not cvss_str:
            return None

        match = re.search(r'(\d+\.?\d*)', str(cvss_str))
        if match:
            try:
                score = float(match.group(1))
                return score if 0 <= score <= 10 else None
            except ValueError:
                pass
        return None

    def _extract_cve(self, cve_str: Optional[str]) -> Optional[str]:
        """Extract CVE ID from string"""
        if not cve_str:
            return None

        match = re.search(r'CVE-\d{4}-\d+', str(cve_str), re.IGNORECASE)
        if match:
            return match.group(0).upper()
        return None

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
            if host and host != 'unknown':
                stats['unique_hosts'].add(host)

        stats['unique_hosts'] = len(stats['unique_hosts'])
        return stats