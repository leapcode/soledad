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
    'leap.common',
    'pysqlcipher',
    'python-gnupg',
    'simplejson',
    'twisted>=12.0.0',  # TODO: maybe we just want twisted-web?
    'oauth',
    'u1db',
    'requests',
    'six==1.1.0',
    'pysqlite',
    'scrypt',
]


tests_requirements = [
    'mock',
    'nose2',
    'testscenarios',
]


if os.environ.get('VIRTUAL_ENV', None):
    data_files = None
else:
    # XXX this should go only for linux/mac
    data_files = [("/etc/init.d/", ["pkg/soledad"])]


setup(
    name='leap.soledad',
    # TODO: change version according to decisions regarding soledad versus
    # leap client versions.
    version='0.1.0',
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
    namespace_packages=["leap"],
    # For now, we do not exclude tests because of the circular dependency
    # between leap.common and leap.soledad.
    #packages=find_packages('src', exclude=['leap.soledad.tests']),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    test_suite='leap.soledad.tests',
    install_requires=install_requirements,
    tests_require=tests_requirements,
    data_files=data_files,
    # the following files are only used for testing, and might be removed if
    # we manage or decide to not install tests in the future.
    package_data={
        'leap.soledad.tests.u1db_tests.testing-certs': [
            '*.pem', '*.cert', '*.key'
        ]
    }
)
