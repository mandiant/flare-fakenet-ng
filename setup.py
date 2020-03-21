import os
import platform

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

requirements = [
    "pydivert",
    "dpkt",
    "dnslib",
    "netifaces",
    "pyftpdlib",
    "cryptography",
    "pyopenssl",
]

if platform.system() == 'Windows':
    requirements.append("pydivert")
elif platform.system().lower().startswith('linux'):
    requirements.append("netfilterqueue")

setup(
    name='FakeNet NG',
    version='1.4.11',
    description="",
    long_description="",
    author="FireEye FLARE Team with credit to Peter Kacherginsky as the original developer",
    author_email='FakeNet@fireeye.com',
    url='https://www.github.com/fireeye/flare-fakenet-ng',
    packages=[
        'fakenet',
    ],
    package_dir={'fakenet': 'fakenet'},
    package_data={'fakenet': ['*.pem','diverters/*.py', 'listeners/*.py',
        'listeners/ssl_utils/*.py', 'listeners/ssl_utils/*.pem', 'configs/*.ini', 'defaultFiles/*',
        'lib/64/*', 'lib/32/*']},
    entry_points={
        "console_scripts": [
            "fakenet=fakenet.fakenet:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='fakenet-ng',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
    ],
)
