from setuptools import setup, find_packages
from os import path

with open('glorifiedgrep/__version__.py', 'r') as f:
    exec(f.read())


def read_requirements():
    with open('requirements.txt') as f:
        return f.read().splitlines()


this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    long_description=long_description,
    long_description_content_type='text/markdown',
    name="glorifiedgrep",
    version=__version__,
    author=__author__,
    packages=find_packages(exclude=('tests')),
    install_requires=[
        'ripgrepy',
        'asn1crypto==0.24.0',
        'cffi==1.11.5',
        'cryptography==2.3.1',
        'idna==2.7',
        'javaobj-py3==0.2.4',
        'pyasn1-modules==0.2.2',
        'pyasn1==0.4.4',
        'pycparser==2.18',
        'pycryptodome==3.6.6',
        'pyjks==18.0.0',
        'pyopenssl==18.0.0',
        'python-magic',
        'six==1.11.0',
        'twofish==0.3.0',
        'xmltodict==0.11.0',
    ],
    classifiers=[
        "Programming Language :: Python :: 3.7"
    ]
)
