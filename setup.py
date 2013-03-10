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
    'pysqlite',
    # TODO: add dependency for leap client ?
    # TODO: add dependency for pysqlcipher.
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
    tests_requires=tests_requirements,
)
