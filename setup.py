"""GRC Threat Modeler - Setup Configuration."""

from setuptools import setup, find_packages

setup(
    name="grc-threat-modeler",
    version="0.1.0",
    description="Automated GRC compliance gap analysis and threat modeling with MITRE ATT&CK mapping",
    author="barec",
    python_requires=">=3.9",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pydantic>=2.0",
        "pandas>=2.0",
        "openpyxl>=3.1",
        "pdfplumber>=0.10",
        "pyyaml>=6.0",
        "rich>=13.0",
        "stix2>=3.0",
    ],
    entry_points={
        "console_scripts": [
            "grc-modeler=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
    ],
)
