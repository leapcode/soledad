from setuptools import (
    setup,
    find_packages
)


install_requirements = [
    'python-gnupg',
    'u1db',
    'oauth',
    'couchdb',
    'configparser',
    'simplejson',
    'pysqlcipher',
    'leap.common',
]


# TODO: change below so we get stable versions of modules.
dependency_links = [
    'git+git://git.futeisha.org/pysqlcipher.git@develop#egg=pysqlcipher',
    'git+ssh://code.leap.se/leap_pycommon.git@develop#egg=leap_pycommon',
]


tests_requirements = [
    'nose2',
    'testscenarios',
]


setup(
    name='leap.soledad',
    # TODO: change version according to decisions regarding soledad versus
    # leap client versions.
    version='0.0.1-dev',
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
    package_dir = {'': 'src'},
    test_suite='nose2.collector.collector',
    install_requires=install_requirements,
    tests_require=tests_requirements,
    dependency_links=dependency_links
)
