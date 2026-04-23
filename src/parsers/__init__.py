"""GRC Threat Modeler - Parsers Package."""

from src.parsers.parser_factory import get_parser
from src.parsers.base_parser import BaseParser

__all__ = ["get_parser", "BaseParser"]
