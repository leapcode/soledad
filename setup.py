from setuptools import setup


requirements = [
    'python-gnupg',
    'u1db',
    'oauth',
    'couchdb',
    'configparser',
    # TODO: add a dependency for leap client
    #'leap_client',
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
    packages=['leap', 'leap.soledad', 'leap.soledad.backends'],
    package_dir = {'': 'src'},
    test_suite='leap.soledad.tests',
    install_requires=requirements,
)

