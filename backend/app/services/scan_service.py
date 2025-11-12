from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, Dict
import logging
from datetime import datetime
import uuid

from app.models.scan import Scan
from app.models.finding import Finding
from app.services.parser_service import ParserService

logger = logging.getLogger(__name__)

class ScanService:
    """Service for managing vulnerability scans"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.parser_service = ParserService()
    
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
        
        return scan
    
    async def process_scan_file(self, scan_id: uuid.UUID, file_content: bytes) -> Dict:
        """
        Process uploaded scan file and create findings
        
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
            # Parse the file
            parsed_data = self.parser_service.parse_file(
                file_content,
                scan.source_tool
            )
            
            # Create findings from parsed data
            findings_created = 0
            for finding_data in parsed_data['findings']:
                finding = await self._create_finding(scan.id, finding_data)
                if finding:
                    findings_created += 1
            
            # Update scan record with statistics
            scan.processed = True
            scan.total_findings = findings_created
            scan.critical_count = parsed_data['statistics'].get('CRITICAL', 0)
            scan.high_count = parsed_data['statistics'].get('HIGH', 0)
            scan.medium_count = parsed_data['statistics'].get('MEDIUM', 0)
            scan.low_count = parsed_data['statistics'].get('LOW', 0)
            scan.info_count = parsed_data['statistics'].get('INFO', 0)
            
            await self.db.commit()
            
            logger.info(f"Successfully processed scan {scan_id}: {findings_created} findings created")
            
            return {
                'scan_id': str(scan.id),
                'findings_created': findings_created,
                'statistics': parsed_data['statistics'],
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {str(e)}")
            scan.processed = False
            scan.processing_error = str(e)
            await self.db.commit()
            
            return {
                'scan_id': str(scan.id),
                'success': False,
                'error': str(e)
            }
    
    async def _create_finding(self, scan_id: uuid.UUID, finding_data: Dict) -> Optional[Finding]:
        """Create a finding record from parsed data"""
        try:
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
                port=int(finding_data.get('port')) if finding_data.get('port') else None,
                protocol=finding_data.get('protocol'),
                service=finding_data.get('service'),
                evidence=finding_data.get('evidence'),
                status='open',
                detected_date=datetime.utcnow()
            )
            
            self.db.add(finding)
            return finding
            
        except Exception as e:
            logger.error(f"Error creating finding: {str(e)}")
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