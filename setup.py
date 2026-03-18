"""Package configuration for GREENWIRE."""

from setuptools import find_packages, setup

setup(
    name="greenwire",
    version="4.0.0",
    description="GREENWIRE – version 4.x",
    license="GPL-2.0",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "greenwire=greenwire.main:run",
        ],
    },
)
