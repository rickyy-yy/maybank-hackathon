import csv
import re
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class GenericCSVParser:
    """Parse generic CSV vulnerability scan reports - supports multiple formats"""

    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO',
        'informational': 'INFO',
        'n/a': 'INFO',
        '4': 'CRITICAL',
        '3': 'HIGH',
        '2': 'MEDIUM',
        '1': 'LOW',
        '0': 'INFO'
    }
    
    # Column name patterns for different CSV formats
    COLUMN_PATTERNS = {
        'cve': ['cve', 'cve id', 'cve_id', 'cve-id'],
        'title': ['title', 'name', 'vulnerability', 'vulnerability title', 'vuln_name', 'plugin name'],
        'description': ['description', 'vulnerability description', 'synopsis', 'details'],
        'severity': ['severity', 'risk', 'cvss severity', 'priority', 'level'],
        'cvss_score': ['cvss', 'cvss score', 'cvss v3.0 base score', 'cvss_score', 'base score'],
        'host': ['host', 'ip', 'ip address', 'target', 'hostname', 'asset'],
        'port': ['port'],
        'protocol': ['protocol'],
        'solution': ['solution', 'remediation', 'fix'],
        'reference': ['reference', 'see also', 'references'],
        'plugin_id': ['plugin id', 'plugin_id', 'no']
    }

    def validate(self, file_content: bytes) -> bool:
        """Validate if file is a valid CSV"""
        try:
            content = file_content.decode('utf-8-sig')  # Handle BOM
            lines = content.strip().split('\n')
            
            if len(lines) < 2:
                return False
            
            # Check if it looks like CSV
            reader = csv.reader(lines[:5])
            rows = list(reader)
            return len(rows) >= 2 and len(rows[0]) >= 3
            
        except Exception as e:
            logger.error(f"CSV validation error: {e}")
            return False

    def parse(self, file_content: bytes) -> Dict:
        """Parse generic CSV vulnerability report"""
        content = file_content.decode('utf-8-sig').strip()
        lines = content.split('\n')

        if len(lines) < 2:
            raise ValueError("CSV file is empty or has no data rows")

        # Detect delimiter
        delimiter = self._detect_delimiter(lines[0])
        
        # Parse CSV
        reader = csv.DictReader(lines, delimiter=delimiter)
        
        # Map columns to standard fields
        column_mapping = self._map_columns(reader.fieldnames or [])
        
        findings = []
        for row_num, row in enumerate(reader, start=2):
            try:
                finding = self._parse_row(row, row_num, column_mapping)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Error parsing row {row_num}: {e}")
                continue

        if not findings:
            if reader.fieldnames:
                logger.warning(f"CSV Headers found: {reader.fieldnames}")
            raise ValueError(
                "No valid vulnerability findings found in CSV. "
                "Please ensure your CSV has columns like: title/name/vulnerability, "
                "severity/risk, host/ip/target, and optionally: port, cve, cvss, description"
            )

        statistics = self._calculate_statistics(findings)

        return {
            'scan_name': 'CSV Vulnerability Scan',
            'scan_date': datetime.utcnow(),
            'total_findings': len(findings),
            'findings': findings,
            'statistics': statistics,
            'metadata': {'scanner': 'csv', 'format': 'csv'}
        }

    def _detect_delimiter(self, header_line: str) -> str:
        """Detect CSV delimiter"""
        delimiters = [',', ';', '\t', '|']
        counts = {d: header_line.count(d) for d in delimiters}
        return max(counts, key=counts.get)
    
    def _map_columns(self, fieldnames: List[str]) -> Dict[str, str]:
        """Map CSV columns to standard field names"""
        mapping = {}
        
        # Normalize fieldnames
        normalized_fields = {fname.lower().strip(): fname for fname in fieldnames}
        
        for standard_field, patterns in self.COLUMN_PATTERNS.items():
            for pattern in patterns:
                if pattern in normalized_fields:
                    mapping[standard_field] = normalized_fields[pattern]
                    break
        
        logger.info(f"Column mapping: {mapping}")
        return mapping

    def _parse_row(self, row: Dict, row_num: int, column_mapping: Dict[str, str]) -> Optional[Dict]:
        """Parse a single CSV row into a finding"""
        
        # Extract fields using column mapping
        def get_field(field_name: str) -> Optional[str]:
            col = column_mapping.get(field_name)
            if col:
                value = row.get(col, '').strip()
                return value if value and value.lower() != 'n/a' else None
            return None
        
        # Get core fields
        title = get_field('title')
        cve = get_field('cve')
        description = get_field('description')
        severity = get_field('severity')
        cvss_score = get_field('cvss_score')
        host = get_field('host')
        port = get_field('port')
        protocol = get_field('protocol')
        solution = get_field('solution')
        reference = get_field('reference')
        plugin_id = get_field('plugin_id')

        # Require at least a title or CVE to consider it a valid finding
        if not title and not cve:
            logger.debug(f"Row {row_num} missing both title and CVE, skipping")
            return None

        # If we have CVE but no title, use CVE as title
        if not title and cve:
            title = cve
            
        # If we have title but no description, use title as description
        if not description:
            description = title

        # Normalize severity
        severity_normalized = self._normalize_severity(severity)

        # Parse CVSS score
        cvss_score_parsed = self._parse_cvss(cvss_score)

        # Parse port
        port_number = self._parse_port(port)

        # Clean CVE
        cve_id = self._clean_cve(cve)
        
        # Use host or default
        affected_host = host or 'unknown'

        finding = {
            'plugin_id': plugin_id or f"csv-{row_num}",
            'title': title[:255] if title else f"Finding from row {row_num}",
            'description': description or title or f"Vulnerability finding from CSV row {row_num}",
            'severity': severity_normalized,
            'affected_host': affected_host,
            'port': port_number,
            'protocol': protocol or 'tcp',
            'service': 'unknown',
            'host_properties': {'ip': affected_host} if affected_host != 'unknown' else {},
            'cvss_score': cvss_score_parsed,
            'cve_id': cve_id,
            'cwe_id': None,
            'evidence': reference,
            'solution': solution
        }

        return finding

    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity to standard values"""
        if not severity:
            return 'INFO'

        severity_lower = severity.lower().strip()
        return self.SEVERITY_MAP.get(severity_lower, 'INFO')

    def _parse_cvss(self, cvss: Optional[str]) -> Optional[float]:
        """Parse CVSS score from string"""
        if not cvss:
            return None

        try:
            # Extract numeric value
            match = re.search(r'(\d+\.?\d*)', cvss)
            if match:
                score = float(match.group(1))
                return score if 0 <= score <= 10 else None
        except (ValueError, AttributeError):
            pass

        return None

    def _parse_port(self, port: Optional[str]) -> Optional[int]:
        """Parse port number from string"""
        if not port:
            return None

        try:
            # Extract numeric port
            match = re.search(r'(\d+)', str(port))
            if match:
                return int(match.group(1))
        except (ValueError, AttributeError):
            pass

        return None

    def _clean_cve(self, cve: Optional[str]) -> Optional[str]:
        """Clean and validate CVE ID - take first one if multiple"""
        if not cve:
            return None

        # Extract all CVE patterns
        matches = re.findall(r'CVE-\d{4}-\d+', cve, re.IGNORECASE)
        if matches:
            # Return the first CVE found
            return matches[0].upper()

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