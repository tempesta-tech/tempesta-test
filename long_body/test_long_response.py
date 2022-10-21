""" Testing for long body in response """

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from helpers import control, remote, tempesta, tf_cfg
from testers import stress

from . import body_generator


class ResponseTestBase(stress.StressTest):
    """Test long response"""

    config = "cache 0;\n"
    filename = "long.bin"
    uri = "/" + filename
    fullname = ""

    def create_content(self, length):
        """Create content file"""
        content = body_generator.generate_body(length)
        location = tf_cfg.cfg.get("Server", "resources")
        self.fullname = os.path.join(location, self.filename)
        tf_cfg.dbg(3, "Copy %s to %s" % (self.filename, self.fullname))
        remote.server.copy_file(self.fullname, content)

    def remove_content(self):
        """Remove content file"""
        if not remote.DEBUG_FILES:
            tf_cfg.dbg(3, "Remove %s" % self.fullname)
            remote.server.run_cmd("rm %s" % self.fullname)

    def tearDown(self):
        super(ResponseTestBase, self).tearDown()
        self.remove_content()

    def create_clients(self):
        """Create wrk with specified uri"""
        self.wrk = control.Wrk(uri=self.uri)
        self.wrk.set_script("foo", content="")
        self.clients = [self.wrk]

    def create_servers_with_body(self, length):
        """Create nginx server with long response body"""
        self.create_content(length)
        port = tempesta.upstream_port_start_from()
        nginx = control.Nginx(listen_port=port)
        self.servers = [nginx]


class ResponseTest1k(ResponseTestBase):
    """1k test"""

    def create_servers(self):
        self.create_servers_with_body(1024)

    def test(self):
        """Test for 1kbyte body"""
        self.generic_test_routine(self.config)


class ResponseTest1M(ResponseTestBase):
    """1M test"""

    def create_servers(self):
        self.create_servers_with_body(1024**2)

    def test(self):
        """Test for 1Mbyte body"""
        self.generic_test_routine(self.config)
