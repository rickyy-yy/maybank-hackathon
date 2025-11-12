from typing import Dict, Optional
from app.parsers.nessus_parser import NessusParser
import logging

logger = logging.getLogger(__name__)

class ParserService:
    """Service for parsing vulnerability scan files"""
    
    def __init__(self):
        self.parsers = {
            'nessus': NessusParser(),
        }
    
    def parse_file(self, file_content: bytes, source_tool: str) -> Dict:
        """
        Parse scan file using appropriate parser
        
        Args:
            file_content: Raw file bytes
            source_tool: Tool that generated the scan (nessus, burp, nmap)
            
        Returns:
            Parsed scan data with findings
            
        Raises:
            ValueError: If parser not found or parsing fails
        """
        parser = self.parsers.get(source_tool.lower())
        
        if not parser:
            raise ValueError(f"No parser available for tool: {source_tool}")
        
        if not parser.validate(file_content):
            raise ValueError(f"Invalid {source_tool} file format")
        
        try:
            result = parser.parse(file_content)
            logger.info(f"Successfully parsed {source_tool} file with {result['total_findings']} findings")
            return result
        except Exception as e:
            logger.error(f"Error parsing {source_tool} file: {str(e)}")
            raise ValueError(f"Failed to parse {source_tool} file: {str(e)}")