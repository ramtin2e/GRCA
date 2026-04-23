import os
import sys
from pathlib import Path

def get_resource_path(relative_path: str) -> Path:
    """
    Get the absolute path to a resource, works for dev and for PyInstaller.
    
    PyInstaller creates a temporary folder and stores path in _MEIPASS.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        # Standard execution: use the project root (assumed to be 2 levels up from this file)
        base_path = Path(__file__).parent.parent.parent
    
    return base_path / relative_path

def get_app_root() -> Path:
    """Get the root directory of the application."""
    try:
        return Path(sys._MEIPASS)
    except AttributeError:
        return Path(__file__).parent.parent.parent
