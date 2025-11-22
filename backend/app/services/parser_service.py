from typing import Dict, Optional
from app.parsers.nessus_parser import NessusParser
from app.parsers.nmap_parser import NmapParser
from app.parsers.markdown_parser import MarkdownParser
from app.parsers.csv_parser import GenericCSVParser
import logging
import os

logger = logging.getLogger(__name__)


class ParserService:
    """Service for parsing vulnerability scan files"""

    def __init__(self):
        self.parsers = {
            'nessus': NessusParser(),
            'nmap': NmapParser(),
            'markdown': MarkdownParser(),
            'csv': GenericCSVParser(),
        }

    def detect_file_type(self, file_content: bytes, filename: str) -> Optional[str]:
        """
        Auto-detect file type based on content and extension

        Args:
            file_content: Raw file bytes
            filename: Original filename

        Returns:
            Detected parser type or None
        """
        file_ext = os.path.splitext(filename)[1].lower()

        # Try to detect by extension first
        ext_map = {
            '.nessus': 'nessus',
            '.xml': None,  # Need content detection for XML
            '.csv': 'csv',
            '.md': 'markdown',
            '.markdown': 'markdown',
        }

        parser_type = ext_map.get(file_ext)

        # For XML files, detect by content
        if file_ext == '.xml':
            try:
                content_str = file_content.decode('utf-8', errors='ignore')[:1000]

                if 'NessusClientData' in content_str:
                    parser_type = 'nessus'
                elif 'nmaprun' in content_str:
                    parser_type = 'nmap'
            except Exception as e:
                logger.warning(f"Error detecting XML type: {e}")

        # Validate detected type
        if parser_type and parser_type in self.parsers:
            parser = self.parsers[parser_type]

            # Special handling for Nmap XML validation
            if parser_type == 'nmap':
                if parser.validate(file_content, file_ext):
                    return parser_type
            else:
                if parser.validate(file_content):
                    return parser_type

        # Try all parsers if auto-detection failed
        for name, parser in self.parsers.items():
            try:
                if name == 'nmap':
                    if parser.validate(file_content, file_ext):
                        return name
                else:
                    if parser.validate(file_content):
                        return name
            except Exception as e:
                logger.debug(f"Parser {name} validation failed: {e}")
                continue

        return None

    def parse_file(self, file_content: bytes, source_tool: str, filename: str = '') -> Dict:
        """
        Parse scan file using appropriate parser

        Args:
            file_content: Raw file bytes
            source_tool: Tool that generated the scan (nessus, nmap, markdown, csv, auto)
            filename: Original filename for auto-detection

        Returns:
            Parsed scan data with findings

        Raises:
            ValueError: If parser not found or parsing fails
        """
        # Auto-detect if requested
        if source_tool.lower() == 'auto':
            detected_type = self.detect_file_type(file_content, filename)
            if not detected_type:
                raise ValueError(
                    f"Could not auto-detect file type for {filename}. "
                    "Please specify the scanner tool explicitly."
                )
            source_tool = detected_type
            logger.info(f"Auto-detected file type: {source_tool}")

        parser = self.parsers.get(source_tool.lower())

        if not parser:
            raise ValueError(
                f"No parser available for tool: {source_tool}. "
                f"Available parsers: {', '.join(self.parsers.keys())}"
            )

        # Validate file format
        file_ext = os.path.splitext(filename)[1].lower() if filename else ''

        try:
            # Special validation for Nmap (needs file extension)
            if source_tool.lower() == 'nmap':
                if not parser.validate(file_content, file_ext):
                    raise ValueError(f"Invalid {source_tool} file format")
            else:
                if not parser.validate(file_content):
                    raise ValueError(f"Invalid {source_tool} file format")
        except Exception as e:
            raise ValueError(f"File validation failed for {source_tool}: {str(e)}")

        # Parse the file
        try:
            # Special parsing for Nmap (needs file extension)
            if source_tool.lower() == 'nmap':
                result = parser.parse(file_content, file_ext)
            else:
                result = parser.parse(file_content)

            logger.info(
                f"Successfully parsed {source_tool} file with "
                f"{result['total_findings']} findings"
            )
            return result

        except Exception as e:
            logger.error(f"Error parsing {source_tool} file: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to parse {source_tool} file: {str(e)}")