from setuptools import setup
from setuptools import find_packages


setup(
    name='test_soledad',
    packages=find_packages('.'),
    package_data={'': ['*.conf', 'u1db_tests/testing-certs/*']}
)
