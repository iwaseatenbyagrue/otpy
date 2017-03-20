# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name='otpy',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[u'Click', u'click-plugins', u'marshmallow'],
    extras_require={u'dev': [u'pytest', u'pytest-pep8', u'pytest-cov']},
    entry_points='''
[console_scripts]
otpy=otpy.cli:base
    '''
)
