"""
A Scalability Test Controller application.
"""

from setuptools import setup, find_packages


client = [
    'funkload',
]

server = [
    'psutil',
    'twisted',
    'leap.soledad',
]

extras = {
    'client': client,
    'server': server,
}

setup(
    name="test-controller",
    version="0.1",
    long_description=__doc__,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    extras_require=extras,
)
