from setuptools import setup, find_packages

setup(
    name="portscan-lite",
    version="1.0.0",
    description="A simple port scanner with banner grabbing",
    packages=find_packages(),
    install_requires=[
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "portscan=portscan_lite.scanner:main",
        ],
    },
    python_requires=">=3.9",
)
