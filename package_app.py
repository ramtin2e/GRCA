"""
GRCA Packaging Script
Automates the creation of a single-file executable using PyInstaller.
"""

import os
import subprocess
import sys
from pathlib import Path

def package():
    # 1. Define paths
    project_root = Path(__file__).parent.absolute()
    launcher = project_root / "desktop_launcher.py"
    
    # 2. Build the command
    # We use sys.executable -m PyInstaller to ensure we use the same Python environment
    # --onefile: Create a single executable
    # --windowed / --noconsole: Don't show a terminal window
    # --add-data: Include static assets and mapping data
    # On Windows, use ; to separate paths. On Mac/Linux, use :
    sep = ";" if sys.platform == "win32" else ":"
    
    # Massive libraries to ignore to prevent crashes and keep the .exe size reasonable
    exclusions = [
        "torch", "torchvision", "torchaudio", "tensorflow", "onnx", "onnxruntime",
        "matplotlib", "scipy", "notebook", "ipython", "PIL", "PyQt5", "PySide2", "PySide6",
        "ultralytics", "cv2", "tensorboard"
    ]
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconsole",
        "--onefile",
        "--name", "GRCA_Threat_Modeler",
        f"--add-data", f"web/static{sep}web/static",
        f"--add-data", f"data/mappings{sep}data/mappings",
        f"--add-data", f"config/profiles{sep}config/profiles",
        f"--add-data", f"data/sample_reports{sep}data/sample_reports",
        str(launcher)
    ]
    
    for mod in exclusions:
        cmd.extend(["--exclude-module", mod])
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        subprocess.run(cmd, check=True)
        print("\nSUCCESS! Your application is in the 'dist' folder.")
    except subprocess.CalledProcessError as e:
        print(f"\nERROR: Packaging failed with exit code {e.returncode}")
    except FileNotFoundError:
        print("\nERROR: PyInstaller not found. Please run 'pip install pyinstaller' first.")

if __name__ == '__main__':
    package()
