from setuptools import setup, find_packages

setup(
    name="greenwire",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyscard>=2.0.0",
        "nfcpy>=1.0.4",
        "cryptography>=41.0.0",
    ],
)
