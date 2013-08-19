# -*- coding: utf-8 -*-
# setup.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import os
from setuptools import (
    setup,
    find_packages
)


install_requirements = [
    'configparser',
    'couchdb',
    'simplejson',
    'twisted>=12.0.0',  # TODO: maybe we just want twisted-web?
    'oauth',  # this is not strictly needed by us, but we need it
              # until u1db adds it to its release as a dep.
    'u1db',
    'routes',
    'PyOpenSSL',
    'leap.soledad.common>=0.3.0',
]


if os.environ.get('VIRTUAL_ENV', None):
    data_files = None
else:
    # XXX this should go only for linux/mac
    data_files = [("/etc/init.d/", ["pkg/soledad"])]


trove_classifiers = (
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: "
    "GNU General Public License v3 or later (GPLv3+)",
    "Environment :: Console",
    "Operating System :: OS Independent",
    "Operating System :: POSIX",
    "Programming Language :: Python :: 2.6",
    "Programming Language :: Python :: 2.7",
    "Topic :: Database :: Front-Ends",
    "Topic :: Software Development :: Libraries :: Python Modules"
)


setup(
    name='leap.soledad.server',
    version='0.3.0',
    url='https://leap.se/',
    license='GPLv3+',
    description='Synchronization of locally encrypted data among devices.',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    long_description=(
        "Soledad is the part of LEAP that allows application data to be "
        "securely shared among devices. It provides, to other parts of the "
        "LEAP client, an API for data storage and sync."
    ),
    namespace_packages=["leap", "leap.soledad"],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=install_requirements,
    data_files=data_files,
    classifiers=trove_classifiers,
)
