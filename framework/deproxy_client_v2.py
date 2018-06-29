from helpers import tf_cfg, remote, stateful

import os
import http.client
import time

class DeproxyClient(stateful.Stateful):
    
    def __init__(self, listen, addr, port):
        curpath = os.path.dirname(__file__)
        client = curpath + '/deproxy_client/client_proxy.py'
        self.listen = listen
        self.client = os.path.normpath(client)
        self.addr = addr
        self.port = port
        self.workdir = tf_cfg.cfg.get('Client', 'workdir')
        self.remotepath = os.path.normpath(self.workdir + '/client_proxy.py')
        self.pidfile = '/tmp/proxy-%i.pid' % self.listen
        self.stop_procedures = [self.__stop]

    def run_start(self):
        tf_cfg.dbg(3, "Starting deproxy client v2")
        remote.client.copy_file_to_node(self.client, self.workdir)
        cmd = "%s -l %i" % (self.remotepath, self.listen)
        remote.client.run_cmd(cmd, ignore_stderr=True)
        self.conn = http.client.HTTPConnection("127.0.0.1", port=self.listen)
        self.conn.connect()

    def __stop(self):
        tf_cfg.dbg(3, "Stopping deproxy client v2")
        cmd = ' && '.join([
            '[ -e \'%s\' ]' % self.pidfile,
            'pid=$(cat %s)' % self.pidfile,
            'kill -s TERM $pid',
            'while [ -e \'/proc/$pid\' ]; do sleep 1; done'
        ])
        remote.client.run_cmd(cmd, ignore_stderr=True)

    def __send_connect(self, addr, port):
        hdrs = {'Command' : 'connect',
                'Addr' : str(addr),
                'Port' : str(port)
                }
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client')

    def __send_request(self, content):
        cl = len(content)
        hdrs = {'Command' : 'connect',
                'Content-Length' : str(cl),
                }
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client')

    def __send_read(self, maxlen):
        hdrs = {'Command' : 'read',
                'Maxlen' : str(maxlen),
                }
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client')
        cl = resp.getheader('Content-Length')
        try:
            return int(cl), resp.read()
        except:
            raise Exception('Problem connecting to proxy client')

    def make_request(self, content):
        self.__send_connect(self.addr, self.port)
        self.__send_request(content)
    
    def wait_for_response(self, expect_length, timeout=5):
        total_len = 0
        total_body = ""
        t1 = time.time()
        while total_len < expect_length:
            l, body = self.__send_read(expect_length)
            total_len += l
            total_body += body
            t2 = time.time()
            if t2 - t1 > timeout:
                break
        return total_len, total_body
