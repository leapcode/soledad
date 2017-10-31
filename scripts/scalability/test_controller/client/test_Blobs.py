import base64
import os
import subprocess
import unittest
import urlparse
import threading

from funkload.FunkLoadTestCase import FunkLoadTestCase
from webunit.utility import Upload


SIZE = 100  # KB
DELETE_ON_SETUP = False
DELETE_ON_TEARDOWN = False


def _get_auth_header(user_id):
    encoded = base64.b64encode('%s:%s-token' % (user_id, user_id))
    return 'Token %s' % encoded


def _ensure_template(templates_dir, size):
    fname = '%dK-0.blob' % size
    fpath = os.path.join(templates_dir, fname)
    if not os.path.isfile(fpath):
        dirname = os.path.dirname(os.path.realpath(__file__))
        executable = os.path.join(dirname, 'templates.py')
        code = subprocess.check_call([
            executable,
            '--amount', '1',
            '--size', str(size),
            templates_dir,
        ])
        assert code == 0, 'failed creating template'
    return fpath


class Blobs(FunkLoadTestCase):

    next_blob_id = 0
    lock = threading.Lock()

    def _get_next_blob_id(self):
        with Blobs.lock:
            blob_id = Blobs.next_blob_id
            Blobs.next_blob_id += 1
            Blobs.next_blob_id %= 5000
        return blob_id

    def setUp(self):
        blob_id = self._get_next_blob_id()
        base_url = self.conf_get('main', 'url')
        self.url = urlparse.urljoin(base_url, 'blobs/0/%d' % blob_id)
        self.setHeader('Authorization', _get_auth_header('0'))
        templates_dir = self.conf_get('main', 'templates_dir')
        size = self.conf_getInt('main', 'size')
        fpath = _ensure_template(templates_dir, size)
        self.upload = ['file', Upload(fpath)]
        if DELETE_ON_SETUP:
            ret = self.delete(self.url, description='Delete blob on setUp')
            self.assert_(ret.code in [404, 200], 'expected 404 or 200')

    def tearDown(self):
        if DELETE_ON_TEARDOWN:
            ret = self.delete(self.url, description='Delete blob on tearDown')
            self.assert_(ret.code in [404, 200], 'expected 404 or 200')
        self.clearHeaders()

    def test_upload(self):
        ret = self.put(self.url, params=[self.upload],
                       description='Upload blob')
        self.assert_(ret.code == 200, "expecting a 200")

    def test_download(self):
        ret = self.get(self.url, description='Download blob')
        self.assert_(ret.code == 200, "expecting a 200")


if __name__ == '__main__':
    unittest.main()
