import tempfile
import os
import shutil

from leap.soledad.client import Soledad


class SoledadClient(object):

    def __init__(self, uuid, server_url, auth_token):
        self._uuid = uuid
        self._server_url = server_url
        self._auth_token = auth_token
        self._tempdir = None
        self._soledad = None

    @property
    def instance(self):
        if self._soledad is None:
            self._soledad = self._get_soledad_client()
        return self._soledad

    def _get_soledad_client(self):
        self._tempdir = tempfile.mkdtemp()
        return Soledad(
            uuid=self._uuid,
            passphrase=u'123',
            secrets_path=os.path.join(self._tempdir, 'secrets.json'),
            local_db_path=os.path.join(self._tempdir, 'soledad.db'),
            server_url=self._server_url,
            cert_file=None,
            auth_token=self._auth_token,
            secret_id=None,
            defer_encryption=True)

    def close(self):
        if self._soledad is not None:
            self._soledad.close()
        if self._tempdir is not None:
            shutil.rmtree(self._tempdir)
