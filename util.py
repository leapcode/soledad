"""
Utilities for Soledad.
"""

import os
import gnupg
import re
from gnupg import logger


class GPGWrapper(gnupg.GPG):
    """
    This is a temporary class for handling GPG requests, and should be
    replaced by a more general class used throughout the project.
    """

    GNUPG_HOME = os.environ['HOME'] + "/.config/leap/gnupg"
    GNUPG_BINARY = "/usr/bin/gpg"  # this has to be changed based on OS

    def __init__(self, gpghome=GNUPG_HOME, gpgbinary=GNUPG_BINARY):
        super(GPGWrapper, self).__init__(gnupghome=gpghome,
                                         gpgbinary=gpgbinary)

    def find_key(self, email):
        """
        Find user's key based on their email.
        """
        for key in self.list_keys():
            for uid in key['uids']:
                if re.search(email, uid):
                    return key
        raise LookupError("GnuPG public key for %s not found!" % email)

    def encrypt(self, data, recipient, sign=None, always_trust=True,
                passphrase=None, symmetric=False):
        """
        Encrypt data using GPG.
        """
        # TODO: devise a way so we don't need to "always trust".
        return super(GPGWrapper, self).encrypt(data, recipient, sign=sign,
                                               always_trust=always_trust,
                                               passphrase=passphrase,
                                               symmetric=symmetric,
                                               cipher_algo='AES256')

    def decrypt(self, data, always_trust=True, passphrase=None):
        """
        Decrypt data using GPG.
        """
        # TODO: devise a way so we don't need to "always trust".
        return super(GPGWrapper, self).decrypt(data,
                                               always_trust=always_trust,
                                               passphrase=passphrase)

    def send_keys(self, keyserver, *keyids):
        """
        Send keys to a keyserver
        """
        result = self.result_map['list'](self)
        gnupg.logger.debug('send_keys: %r', keyids)
        data = gnupg._make_binary_stream("", self.encoding)
        args = ['--keyserver', keyserver, '--send-keys']
        args.extend(keyids)
        self._handle_io(args, data, result, binary=True)
        gnupg.logger.debug('send_keys result: %r', result.__dict__)
        data.close()
        return result

    def encrypt_file(self, file, recipients, sign=None,
                     always_trust=False, passphrase=None,
                     armor=True, output=None, symmetric=False,
                     cipher_algo=None):
        "Encrypt the message read from the file-like object 'file'"
        args = ['--encrypt']
        if symmetric:
            args = ['--symmetric']
            if cipher_algo:
                args.append('--cipher-algo %s' % cipher_algo)
        else:
            args = ['--encrypt']
            if not _is_sequence(recipients):
                recipients = (recipients,)
            for recipient in recipients:
                args.append('--recipient "%s"' % recipient)
        if armor:  # create ascii-armored output - set to False for binary
            args.append('--armor')
        if output:  # write the output to a file with the specified name
            if os.path.exists(output):
                os.remove(output)  # to avoid overwrite confirmation message
            args.append('--output "%s"' % output)
        if sign:
            args.append('--sign --default-key "%s"' % sign)
        if always_trust:
            args.append("--always-trust")
        result = self.result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase=passphrase, binary=True)
        logger.debug('encrypt result: %r', result.data)
        return result
