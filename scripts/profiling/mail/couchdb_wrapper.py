import re
import os
import tempfile
import subprocess
import time
import shutil


from leap.common.files import mkdir_p


class CouchDBWrapper(object):
    """
    Wrapper for external CouchDB instance.
    """

    def start(self):
        """
        Start a CouchDB instance for a test.
        """
        self.tempdir = tempfile.mkdtemp(suffix='.couch.test')

        path = os.path.join(os.path.dirname(__file__),
                            'couchdb.ini.template')
        handle = open(path)
        conf = handle.read() % {
            'tempdir': self.tempdir,
        }
        handle.close()

        confPath = os.path.join(self.tempdir, 'test.ini')
        handle = open(confPath, 'w')
        handle.write(conf)
        handle.close()

        # create the dirs from the template
        mkdir_p(os.path.join(self.tempdir, 'lib'))
        mkdir_p(os.path.join(self.tempdir, 'log'))
        args = ['couchdb', '-n', '-a', confPath]
        null = open('/dev/null', 'w')

        self.process = subprocess.Popen(
            args, env=None, stdout=null.fileno(), stderr=null.fileno(),
            close_fds=True)
        # find port
        logPath = os.path.join(self.tempdir, 'log', 'couch.log')
        while not os.path.exists(logPath):
            if self.process.poll() is not None:
                got_stdout, got_stderr = "", ""
                if self.process.stdout is not None:
                    got_stdout = self.process.stdout.read()

                if self.process.stderr is not None:
                    got_stderr = self.process.stderr.read()
                raise Exception("""
couchdb exited with code %d.
stdout:
%s
stderr:
%s""" % (
                    self.process.returncode, got_stdout, got_stderr))
            time.sleep(0.01)
        while os.stat(logPath).st_size == 0:
            time.sleep(0.01)
        PORT_RE = re.compile(
            'Apache CouchDB has started on http://127.0.0.1:(?P<port>\d+)')

        handle = open(logPath)
        m = None
        line = handle.readline()
        while m is None:
            m = PORT_RE.search(line)
            line = handle.readline()
        handle.close()
        self.port = int(m.group('port'))

    def stop(self):
        """
        Terminate the CouchDB instance.
        """
        self.process.terminate()
        self.process.communicate()
        shutil.rmtree(self.tempdir)

