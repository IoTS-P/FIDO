#!/usr/bin/env python
"""
    Python package for the fuzzware pipeline.
"""
import os
from setuptools import setup

def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages

setup(name='fuzzware_pipeline',
    version='0.1',
    description='Python package for the fuzzware pipeline.',
    author='Tobias Scharnowski',
    author_email='tobias.scharnowski@rub.de',
    url='https://github.com/RUB-SysSec',
    packages=get_packages('fuzzware_pipeline'),
    entry_points = {
        'console_scripts': [
            'fuzzware = fuzzware_pipeline:main',
        ]
    }
)
