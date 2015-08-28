#!/bin/sh
# Generate wheels for dependencies
# Use at your own risk.

if [ "$WHEELHOUSE" = "" ]; then
    WHEELHOUSE=$HOME/wheelhouse
fi

pip wheel --wheel-dir $WHEELHOUSE pip
pip wheel --wheel-dir $WHEELHOUSE --allow-external u1db --allow-unverified u1db --allow-external dirspec --allow-unverified dirspec -r pkg/requirements.pip
if [ -f pkg/requirements-testing.pip ]; then
   pip wheel --wheel-dir $WHEELHOUSE -r pkg/requirements-testing.pip
fi
