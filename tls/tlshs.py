#!/usr/bin/env python

from optparse import OptionParser

from handshake import tls12_hs

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


def main():
    op = OptionParser()
    op.add_option("-a", "--tfw_addr", dest="addr", metavar="IP",
                  default='127.0.0.1', help="Tempesta FW IP address"
                                            " (default: %default)")
    op.add_option("-p", "--tfw_port", dest="port", metavar="PORT",
                  default=443, help="Tempesta FW listening TLS port"
                                    " (default: %default)")
    op.add_option("-v", "--verbose", dest="verbose", action="store_true",
                  help="verbose mode")
    (cfg, _) = op.parse_args()

    tls12_hs(vars(cfg))


if __name__ == "__main__":
    main()
