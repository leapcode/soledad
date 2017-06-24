# -*- coding: utf-8 -*-
# setup.py
# Copyright (C) 2013-2017 LEAP Encryption Access Project
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
"""
Setup file for leap.soledad
"""
import os
import re
import sys
import versioneer

from setuptools import setup
from setuptools import find_packages
from setuptools.command.develop import develop as _cmd_develop


isset = lambda var: os.environ.get(var, None)
skip = ['VIRTUAL_ENV', 'LEAP_SKIP_INIT', 'READTHEDOCS']
if len(filter(isset, skip)):
    data_files = None
else:
    # XXX this should go only for linux/mac
    data_files = [("/etc/init.d/", ["pkg/server/soledad-server"])]


trove_classifiers = (
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: "
    "GNU General Public License v3 or later (GPLv3+)",
    "Environment :: Console",
    "Operating System :: OS Independent",
    "Operating System :: POSIX",
    "Programming Language :: Python :: 2.7",
    "Topic :: Database :: Front-Ends",
    "Topic :: Software Development :: Libraries :: Python Modules"
)

DOWNLOAD_BASE = ('https://github.com/leapcode/soledad/'
                 'archive/%s.tar.gz')
_versions = versioneer.get_versions()
VERSION = _versions['version']
VERSION_REVISION = _versions['full-revisionid']
DOWNLOAD_URL = ""

# get the short version for the download url
_version_short = re.findall('\d+\.\d+\.\d+', VERSION)
if len(_version_short) > 0:
    VERSION_SHORT = _version_short[0]
    DOWNLOAD_URL = DOWNLOAD_BASE % VERSION_SHORT


class cmd_develop(_cmd_develop):
    def run(self):
        # versioneer:
        versions = versioneer.get_versions(verbose=True)
        self._versioneer_generated_versions = versions
        # unless we update this, the command will keep using the old version
        self.distribution.metadata.version = versions["version"]
        _cmd_develop.run(self)


cmdclass = versioneer.get_cmdclass()
cmdclass["develop"] = cmd_develop

install_requires = [
    'pyasn1',
    'service-identity',
    'twisted',
    'treq',
    'paste',   # deprecate
    'routes',  # deprecate
    'six',
    'leap.common',  # deprecate use of asserts
]

client = [
    'cryptography',
    'scrypt',  # XXX deprecate this, cryptography does with recent openssl
    'zope.proxy',
]

# needed until kali merges the py3 fork back into the main pysqlcipher repo
if sys.version_info.major >= 3:
    client += ['pysqlcipher3']
else:
    client += ['pysqlcipher']

server = [
    'configparser',
    'Beaker',
    'couchdb'
]

signaling = ['leap.common']


extras = {
    'client': client,
    'server': server,
    'signaling': signaling
}

setup(
    name='leap.soledad',
    version=versioneer.get_version(),
    cmdclass=cmdclass,
    url='https://soledad.readthedocs.io/',
    download_url=DOWNLOAD_URL,
    license='GPLv3+',
    description='Synchronization of locally encrypted data among devices.',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    maintainer='Kali Kaneko',
    maintainer_email='kali@leap.se',
    long_description=(
        "Soledad is the part of LEAP that allows application data to be "
        "securely shared among devices. It provides, to other parts of the "
        "LEAP project, an API for data storage and sync."
    ),
    classifiers=trove_classifiers,
    namespace_packages=["leap"],
    packages=find_packages('src', exclude=['*.tests', '*.tests.*']),
    package_dir={'': 'src'},
    package_data={'': ["*.sql"]},
    install_requires=install_requires,
    extras_require=extras,
    data_files=data_files
)
