#! /usr/bin/env python

from __future__ import absolute_import

import se_profile

from setuptools import setup

REQUIRES = [
    "memory_profiler>=0.41",
    "psutil>=5.0.0",
]

setup(
    name='se_profile',
    version=se_profile.__version__,
    scripts=[
        'se_profile/profile.py',
    ],
    packages=[
        'se_profile',
    ],
    install_requires=REQUIRES,
)
