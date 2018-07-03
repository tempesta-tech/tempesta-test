from helpers import tf_cfg, remote, stateful, deproxy

import os
import httplib
import time

class DeproxyClient(stateful.Stateful):
    
    def __init__(self, listen, addr, port):
        stateful.Stateful.__init__(self)
        curpath = os.path.dirname(__file__)
        client = curpath + '/deproxy_client/client_proxy.py'
        self.listen = listen
        self.client = os.path.normpath(client)
        self.addr = addr
        self.port = port
        self.workdir = tf_cfg.cfg.get('Client', 'workdir')
        self.clientip = tf_cfg.cfg.get('Client', 'ip')
        self.remotepath = os.path.normpath(self.workdir + '/client_proxy.py')
        self.pidfile = '%s/proxy-%i.pid' % (self.workdir, self.listen)
        self.stop_procedures = [self.__stop]
        self.response = ""
        self.request = None

    def run_start(self):
        tf_cfg.dbg(3, "\tStarting deproxy client v2")
        remote.client.copy_file_to_node(self.client, self.workdir)
        cmd = "cd %s && %s -l %i" % (self.workdir, self.remotepath, self.listen)
        remote.client.run_cmd(cmd, ignore_stderr=True)
        tf_cfg.dbg(3, "\tDaemon started")
        self.conn = httplib.HTTPConnection(self.clientip, port=self.listen)
        self.conn.connect()
        self.__send_connect(self.addr, self.port)
        tf_cfg.dbg(3, "\tClient started")

    def __stop(self):
        tf_cfg.dbg(3, "\tStopping deproxy client v2")
        self.__send_finish()
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
        tf_cfg.dbg(4, "\tsending connect")
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client: %s' % resp.msg)

    def __send_request(self, content):
        cl = len(content)
        hdrs = {'Command' : 'request',
                'Content-Length' : str(cl),
                }
        tf_cfg.dbg(4, "\tsending request")
        self.conn.request("POST", "/", body=content, headers=hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client: %s' % resp.msg)

    def __send_read(self, maxlen):
        hdrs = {'Command' : 'read',
                'Maxlen' : str(maxlen),
                }
        tf_cfg.dbg(4, "\tsending read")
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client: %s' % resp.msg)
        cl = resp.getheader('Content-Length')
        try:
            return int(cl), resp.read()
        except:
            raise Exception('Problem connecting to proxy client')

    def __send_finish(self):
        hdrs = {'Command' : 'finish'}
        tf_cfg.dbg(4, "\tsending finish")
        self.conn.request("POST", "/", "", hdrs)
        resp = self.conn.getresponse()
        result = resp.getheader('Result')
        if result != 'ok':
            raise Exception('Problem connecting to proxy client: %s' % resp.msg)

    def make_request(self, content):
        self.request = deproxy.Request(content)
        self.__send_request(content)
    
    def wait_for_response(self, timeout=5):
        total_len = 0
        response_buffer = ""

        t1 = time.time()
        wait = True
        while wait:
            t2 = time.time()
            if t2 - t1 > timeout:
                tf_cfg.dbg(3, "\tTimeout")
                return False
            l, body = self.__send_read(4096)
            total_len += l
            response_buffer += body
            try:
                self.response = deproxy.Response(response_buffer,
                                    method=self.request.method)
                response_buffer = response_buffer[total_len:]
                break
            except deproxy.IncompliteMessage:
                continue
            except deproxy.ParseError:
                tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % response_buffer))
                return False

        if len(response_buffer) > 0:
            # TODO: take care about pipelined case
            err = 'Garbage after response end:\n```\n%s\n```\n'
            tf_cfg.dbg(3, deproxy.ParseError(err % response_buffer))
            return False
        return True
