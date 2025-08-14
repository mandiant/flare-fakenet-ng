# Copyright 2025 Google LLC

import os
import platform

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

requirements = [
    "dpkt",
    "dnslib",
    "netifaces",
    "pyftpdlib",
    "cryptography",
    "pyopenssl",
    "jinja2",
]

if platform.system() == "Windows":
    requirements.append("pydivert")
elif platform.system().lower().startswith("linux"):
    requirements.append("netfilterqueue")

setup(
    name="FakeNet NG",
    version="3.5",
    description="",
    long_description="",
    author="Mandiant FLARE Team with credit to Peter Kacherginsky as the original developer",
    author_email="FakeNet@mandiant.com",
    url="https://www.github.com/mandiant/flare-fakenet-ng",
    packages=[
        "fakenet",
    ],
    package_dir={"fakenet": "fakenet"},
    package_data={
        "fakenet": [
            "*.pem",
            "diverters/*.py",
            "listeners/*.py",
            "listeners/ssl_utils/*.py",
            "listeners/ssl_utils/*.pem",
            "configs/*.ini",
            "configs/html_report_template.html",
            "defaultFiles/*",
            "lib/64/*",
            "lib/32/*",
            "configs/*.crt",
            "configs/*.key",
        ]
    },
    entry_points={
        "console_scripts": [
            "fakenet=fakenet.fakenet:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords="fakenet-ng",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
    ],
)
