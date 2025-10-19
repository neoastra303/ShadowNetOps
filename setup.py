"""
RedTeam Terminal - Setup Configuration
"""

from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='redteam-terminal',
    version='2.1.0',
    author='RedTeam Terminal Project',
    author_email='security@redteam-terminal.com',
    description='A comprehensive cybersecurity assessment platform featuring multiple security testing modules for network, web application, wireless, and digital forensics domains.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/your-username/redteam-terminal',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: Software Development :: Testing',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'redteam-terminal=redteam:main',
        ],
    },
    keywords='security, penetration-testing, osint, cybersecurity, red-team, vulnerability-assessment, forensics',
    project_urls={
        'Documentation': 'https://github.com/your-username/redteam-terminal#readme',
        'Source': 'https://github.com/your-username/redteam-terminal',
        'Tracker': 'https://github.com/your-username/redteam-terminal/issues',
    },
)