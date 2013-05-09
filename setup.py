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
    'oauth',
    'pysqlcipher',
    'python-gnupg',
    'simplejson',
    # "Installation of Twisted using easy_install with a local source directory
    # is supported. In the past there have been problems using these tools to
    # upgrade an existing version of Twisted, and these problems likely still
    # exist. Similarly, there are often problems when Twisted is declared as a
    # dependency by another project using the setuptools distutils extensions.
    # You should probably not rely on this functionality. Instead, install a
    # platform-supplied package, or install Twisted by downloading a tarball,
    # unpacking it, and running setup.py."
    #   - https://twistedmatrix.com/trac/wiki/FrequentlyAskedQuestions
    'twisted>=12.0.0',  # TODO: maybe we just want twisted-web?
    # twisted cannot be installed separately using pip.
    'u1db',
    'requests',
    'six==1.1',
    'pysqlite',
]


# TODO: change below so we get stable versions of modules.
dependency_links = [
    #'git+git://git.futeisha.org/pysqlcipher.git@develop#egg=pysqlcipher',
    #'git+ssh://code.leap.se/leap_pycommon.git@develop#egg=leap.common',
    'http://twistedmatrix.com/Releases/Twisted/13.0/Twisted-13.0.0.tar.bz2#egg=twisted-13.0.0'
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
    version='0.0.2-dev',
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
    packages=find_packages('src', exclude=['leap.soledad.tests']),
    package_dir={'': 'src'},
    test_suite='leap.soledad.tests',
    install_requires=install_requirements,
    tests_require=tests_requirements,
    dependency_links=dependency_links,
    data_files = data_files
)
