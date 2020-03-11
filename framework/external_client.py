from . import client


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ExternalTester(client.Client):

    def __init__(self, cmd_args, **kwargs):
        client.Client.__init__(self, **kwargs)
        self.options = [cmd_args]

    def form_command(self):
        cmd = ' '.join([self.bin] + self.options)
        return cmd

    def parse_out(self, stdout, stderr):
        return True
