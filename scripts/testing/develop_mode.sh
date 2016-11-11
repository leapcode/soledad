#!/bin/sh
cd common
python setup.py develop
cd ../client
python setup.py develop
cd ../server
python setup.py develop
