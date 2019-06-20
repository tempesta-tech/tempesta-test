#!/usr/bin/env python

from optparse import OptionParser

from handshake import tls12_hs

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


def main():
    opt = OptionParser()
    opt.add_option("-a", "--tfw_addr", dest="addr", metavar="IP",
                   default='127.0.0.1', help="Tempesta FW IP address"
                                             " (default: %default)")
    opt.add_option("-p", "--tfw_port", dest="port", metavar="PORT",
                   default=443, help="Tempesta FW listening TLS port"
                                     " (default: %default)")

    # TODO The buffered IO layers of ScaPy need the timeout to finish
    # reading and return result buffer to upper layer for processing,
    # so it uses the receive timeout. This is bad and wrong: we should
    # return each chunk of read data to TLS processing layer and read
    # from a socket again if a TLS record isn't finished and only the
    # second time, if the sender dies or just sends wrong data, use the
    # timeout to fail.
    opt.add_option("-t", "--rto", dest="rto", default=0.5,
                   help="receive timeout in seconds (default: %default)")

    opt.add_option("-v", "--verbose", dest="verbose", action="store_true",
                   help="verbose mode")
    (cfg, _) = opt.parse_args()

    tls12_hs(vars(cfg))


if __name__ == "__main__":
    main()
