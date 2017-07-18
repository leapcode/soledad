# -*- coding: utf-8 -*-
# _scrypt.py
# Copyright (C) 2017 LEAP Encryption Access Project
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

try:
    from cryptography.hazmat.backends.interfaces import ScryptBackend
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import UnsupportedAlgorithm
    backend = default_backend()
    OPENSSL_HAS_SCRYPT = isinstance(backend, ScryptBackend)
except ImportError:
    OPENSSL_HAS_SCRYPT = False


def _fallback_hash(secret, salt, buflen=32):
    import scrypt
    return scrypt.hash(secret, salt, buflen=buflen)


if OPENSSL_HAS_SCRYPT:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    def hash(secret, salt, buflen=32):
        try:
            _hash = Scrypt(
                salt, buflen, 16384, 8, 1, backend).derive(secret)
        except UnsupportedAlgorithm:
            _hash = _fallback_hash(secret, salt, buflen)
        return _hash

else:
    hash = _fallback_hash
