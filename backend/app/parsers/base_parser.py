from abc import ABC, abstractmethod
from typing import Dict, List

class BaseParser(ABC):
    """Abstract base class for vulnerability scan parsers"""
    
    @abstractmethod
    def parse(self, file_content: bytes) -> Dict:
        """
        Parse scan file and return normalized findings
        
        Args:
            file_content: Raw file bytes
            
        Returns:
            Dictionary containing scan metadata and findings
        """
        pass
    
    @abstractmethod
    def validate(self, file_content: bytes) -> bool:
        """
        Validate if file can be parsed by this parser
        
        Args:
            file_content: Raw file bytes
            
        Returns:
            True if file is valid for this parser
        """
        pass