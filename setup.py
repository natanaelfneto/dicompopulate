#!/usr/bin/env python

import importlib
import os
import re
import setuptools

# project long description
BASE_PATH = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(BASE_PATH, 'README.md'), "r") as file:
    long_description = file.read()

install_requires = [
   'pydicom',
]

github_dependencies = {
    'pynetdicom3': 'https://github.com/pydicom/pynetdicom3.git'
}

# install dependencies only available on github repositories
for dependency in github_dependencies:
    try:
        print('check if dependency module {0} is already installed'.format(dependency))
        i = importlib.import_module(dependency)
        print('{0} [OK]'.format(dependency))
    except Exception as e:
        print('module {0} not found, installing...'.format(dependency))
        try:
            os.system('pip install git+{0}'.format(github_dependencies[dependency]))
        except Exception as e:
            print('Could not install following dependency: {0}'.format(dependency))

# import own module
from populate import populate as module

setuptools.setup(
    name=module.__project__,
    version=module.__version__,
    author=module.__author__,
    author_email=module.__authoremail__,
    description=module.short_description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=module.__source__,
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=install_requires
)