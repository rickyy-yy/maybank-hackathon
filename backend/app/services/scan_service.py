from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import Optional, Dict
import logging
from datetime import datetime
import uuid

from app.models.scan import Scan
from app.models.finding import Finding
from app.services.parser_service import ParserService
from app.services.prioritization_service import PrioritizationService

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing vulnerability scans with full processing pipeline"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.parser_service = ParserService()
        self.prioritization_service = PrioritizationService(db)

    async def create_scan(self, filename: str, source_tool: str) -> Scan:
        """Create a new scan record"""
        scan = Scan(
            filename=filename,
            source_tool=source_tool,
            processed=False
        )

        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        logger.info(f"Created scan record: {scan.id} for file: {filename}")
        return scan

    async def process_scan_file(self, scan_id: uuid.UUID, file_content: bytes) -> Dict:
        """
        Complete scan processing pipeline:
        1. Parse scan file
        2. Create finding records
        3. Calculate risk scores and prioritize
        4. Apply remediation guidance (with web search enhancement)
        5. Update scan statistics

        Args:
            scan_id: UUID of the scan record
            file_content: Raw file bytes

        Returns:
            Processing results with statistics
        """
        # Get scan record
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")

        try:
            logger.info(f"Starting processing pipeline for scan {scan_id}")

            # Step 1: Parse the scan file
            logger.info(f"Step 1/5: Parsing {scan.source_tool} file")
            parsed_data = self.parser_service.parse_file(
                file_content,
                scan.source_tool
            )
            logger.info(f"✓ Parsed {parsed_data['total_findings']} findings")

            # Step 2: Create finding records
            logger.info(f"Step 2/5: Creating finding records")
            findings_created = 0
            for finding_data in parsed_data['findings']:
                finding = await self._create_finding(scan.id, finding_data)
                if finding:
                    findings_created += 1

            # Flush to database so findings have IDs
            await self.db.flush()
            logger.info(f"✓ Created {findings_created} finding records")

            # Step 3: Prioritize findings
            logger.info(f"Step 3/5: Calculating risk scores and priorities")
            prioritization_stats = await self.prioritization_service.prioritize_scan_findings(
                str(scan_id)
            )
            logger.info(f"✓ Prioritization complete (avg score: {prioritization_stats.get('average_score', 0):.1f})")

            # Step 4: Apply remediation guidance with web search
            logger.info(f"Step 4/5: Applying remediation guidance (with web search for critical/high findings)")
            from app.services.remediation_service import RemediationService
            remediation_service = RemediationService(self.db)
            remediation_count = await remediation_service.apply_remediation_to_findings(str(scan_id))
            logger.info(f"✓ Applied remediation guidance to {remediation_count} findings")

            # Step 5: Update scan record with statistics
            logger.info(f"Step 5/5: Updating scan statistics")
            scan.processed = True
            scan.total_findings = findings_created
            scan.critical_count = parsed_data['statistics'].get('CRITICAL', 0)
            scan.high_count = parsed_data['statistics'].get('HIGH', 0)
            scan.medium_count = parsed_data['statistics'].get('MEDIUM', 0)
            scan.low_count = parsed_data['statistics'].get('LOW', 0)
            scan.info_count = parsed_data['statistics'].get('INFO', 0)
            scan.processing_error = None

            await self.db.commit()
            await self.db.refresh(scan)

            logger.info(f"✅ Successfully completed processing for scan {scan_id}")
            logger.info(f"   Critical: {scan.critical_count}, High: {scan.high_count}, Medium: {scan.medium_count}")

            return {
                'scan_id': str(scan.id),
                'findings_created': findings_created,
                'statistics': {
                    'critical': scan.critical_count,
                    'high': scan.high_count,
                    'medium': scan.medium_count,
                    'low': scan.low_count,
                    'info': scan.info_count,
                    'total': scan.total_findings
                },
                'prioritization': prioritization_stats,
                'remediation_applied': remediation_count,
                'success': True
            }

        except Exception as e:
            logger.error(f"❌ Error processing scan {scan_id}: {str(e)}", exc_info=True)

            # Update scan with error status
            scan.processed = False
            scan.processing_error = str(e)
            await self.db.commit()

            return {
                'scan_id': str(scan.id),
                'success': False,
                'error': str(e)
            }

    async def _create_finding(self, scan_id: uuid.UUID, finding_data: Dict) -> Optional[Finding]:
        """Create a finding record from parsed data with all fields"""
        try:
            # Extract host properties
            host_props = finding_data.get('host_properties', {})

            finding = Finding(
                source_scan_id=scan_id,
                source_tool=finding_data.get('plugin_id', ''),
                plugin_id=finding_data.get('plugin_id'),
                title=finding_data.get('title', 'Unknown Vulnerability'),
                description=finding_data.get('description', ''),
                severity=finding_data.get('severity', 'INFO'),
                cvss_score=finding_data.get('cvss_score'),
                cvss_vector=finding_data.get('cvss_vector'),
                cve_id=finding_data.get('cve_id'),
                cwe_id=finding_data.get('cwe_id'),
                affected_asset=finding_data.get('affected_host', 'unknown'),
                asset_hostname=finding_data.get('affected_host'),
                asset_ip=host_props.get('ip'),
                port=int(finding_data.get('port', 0)) if finding_data.get('port') else None,
                protocol=finding_data.get('protocol'),
                service=finding_data.get('service'),
                evidence=finding_data.get('evidence'),
                status='open',
                detected_date=datetime.utcnow(),
                false_positive=False
            )

            self.db.add(finding)
            return finding

        except Exception as e:
            logger.error(f"Error creating finding: {str(e)}", exc_info=True)
            return None

    async def get_scan(self, scan_id: uuid.UUID) -> Optional[Scan]:
        """Get scan by ID"""
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_all_scans(self, limit: int = 50, offset: int = 0):
        """Get all scans with pagination"""
        result = await self.db.execute(
            select(Scan)
            .order_by(Scan.upload_date.desc())
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()

    async def get_scan_status(self, scan_id: uuid.UUID) -> Dict:
        """
        Get detailed status of a scan including processing state

        Args:
            scan_id: UUID of the scan

        Returns:
            Status information dictionary
        """
        scan = await self.get_scan(scan_id)

        if not scan:
            return {
                'scan_id': str(scan_id),
                'status': 'not_found',
                'error': 'Scan not found'
            }

        # Determine status
        if scan.processed:
            status = 'completed'
        elif scan.processing_error:
            status = 'failed'
        else:
            status = 'processing'

        return {
            'scan_id': str(scan.id),
            'status': status,
            'processed': scan.processed,
            'total_findings': scan.total_findings,
            'error': scan.processing_error,
            'statistics': {
                'critical': scan.critical_count,
                'high': scan.high_count,
                'medium': scan.medium_count,
                'low': scan.low_count,
                'info': scan.info_count
            } if scan.processed else None,
            'upload_date': scan.upload_date.isoformat() if scan.upload_date else None,
            'filename': scan.filename,
            'source_tool': scan.source_tool
        }