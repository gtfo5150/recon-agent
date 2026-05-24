from setuptools import setup, find_packages

setup(
    name="recon-agent",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
        "requests>=2.28",
        "python-nmap>=0.7",
        "python-whois>=0.8",
        "dnspython>=2.3",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "recon-agent=recon_agent.cli:main",
        ],
    },
    python_requires=">=3.8",
)
