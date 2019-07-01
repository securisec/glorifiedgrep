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
    install_requires=read_requirements(),
    classifiers=[
        "Programming Language :: Python :: 3.7"
    ]
)
