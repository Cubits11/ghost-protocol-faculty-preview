from setuptools import setup, find_packages

setup(
    name="sra-ghost-protocol",
    version="0.1.0",
    packages=find_packages(include=['sra', 'sra.*', 'attacks', 'attacks.*']),
    python_requires=">=3.8",
)