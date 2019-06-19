# Basic TLS 1.2 handshake test.
#
# Also usable as a TLS traffic generator to debug early TLS server
# implementation. This tool emphasises flexibility in generation of TLS traffic,
# not performance.
#
# ScaPy is still not fully compatible w/ Python3,
# https://github.com/tintinweb/scapy-ssl_tls/issues/39
#
# TLS 1.2 is specified in RFC 5246. See also these useful references:
#   - https://wiki.osdev.org/SSL/TLS
#   - https://wiki.osdev.org/TLS_Handshake
#   - https://wiki.osdev.org/TLS_Encryption

import random
import socket
import sys
import scapy
from scapy_ssl_tls.ssl_tls import *

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def conn_estab(addr, port, rto):
    sd = TLSSocket(socket.socket(), client = True)
    # Set large enough send and receive timeouts which will be used by default.
    sd.settimeout(rto)
    sd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                  struct.pack('ll', 2, rto * 1000))
    sd.connect((addr, port))
    return sd


def send_recv(sd, pkt, rto):
    """
    Mainly a copy&paste from tls_do_round_trip(), but uses custom timeout to
    be able to fully read all data from Tempesta in verbose debugging mode
    (serial console verbose logging may be extremely slow).
    """
    resp = TLS()
    try:
        sd.sendall(pkt)
        resp = sd.recvall(timeout=rto)
        if resp.haslayer(TLSAlert):
            alert = resp[TLSAlert]
            if alert.level != TLSAlertLevel.WARNING:
                level = TLS_ALERT_LEVELS.get(alert.level, "unknown")
                desc = TLS_ALERT_DESCRIPTIONS.get(alert.description,
                                                  "unknown description")
                raise TLSProtocolError("%s alert returned by server: %s"
                                       % (level.upper(), desc.upper()),
                                         pkt, resp)
    except socket.error as se:
        raise TLSProtocolError(se, pkt, resp)
    return resp


def static_rnd(a, b):
    """ A replacement for random.randint() to return constant results. """
    return (a + b) / 2


def tls12_hs(cfg):
    """
    Test TLS 1.2 handshake: establish a new TCP connection and send predefined
    TLS handshake records. This test is suitable for debug build of Tempesta FW,
    which replaces random and time functions with deterministic data. The test
    doesn't actually verify any functionality, but rather just helps to debug
    the core handshake functionality.
    """
    verbose = cfg['verbose']
    rto = cfg['rto']

    try:
        sd = conn_estab(cfg['addr'], cfg['port'], rto)
    except socket.error:
        print("Cannot connect to " + cfg['addr'] + ":" + str(cfg['port'])
              + ": " + str(socket.error))
        return 2

    c_h = TLSClientHello(
            gmt_unix_time = 0x22222222,
            random_bytes = '\x11' * 28,
            cipher_suites = [
                TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
            compression_methods = [TLSCompressionMethod.NULL],
            # EtM isn't supported - just try to negate an unsupported
            # extension.
            extensions = [
                TLSExtension(type = 0x16), # Encrypt-then-MAC
                TLSExtension() / TLSExtECPointsFormat(),
                TLSExtension() / TLSExtSupportedGroups(),
                TLSExtension() / TLSExtSignatureAlgorithms()]
            )
    hs = TLSHandshakes(handshakes=[TLSHandshake() / c_h])
    p = TLSRecord(version='TLS_1_2') / hs
    if verbose:
        p.show()

    # Send ClientHello and read ServerHello, ServerCertificate,
    # ServerKeyExchange, ServerHelloDone.
    s_h = send_recv(sd, p, rto)
    if verbose:
        s_h.show()

    # Send ClientKeyExchange, ChangeCipherSpec.
    # get_client_kex_data() -> get_client_ecdh_pubkey() -> make_keypair()
    # use random, so replace it with our mock.
    randint_save = random.randint
    random.randint = static_rnd
    hs2 = TLSHandshakes(handshakes=[TLSHandshake() /
                                    sd.tls_ctx.get_client_kex_data()])
    random.randint = randint_save
    c_ke = TLSRecord(version='TLS_1_2') / hs2
    c_ccs = TLSRecord(version='TLS_1_2') / TLSChangeCipherSpec()
    if verbose:
        c_ke.show()
        c_ccs.show()

    sd.sendall(TLS.from_records([c_ke, c_ccs]))
    # Now we can calculate the final session checksum, send ClientFinished,
    # and receive ServerFinished.
    f = TLSFinished(data=sd.tls_ctx.get_verify_data())
    hs3 = TLSHandshakes(handshakes=[TLSHandshake() / f])
    c_f = TLSRecord(version='TLS_1_2') / hs3
    if verbose:
        c_f.show()

    s_f = send_recv(sd, c_f, rto)
    if verbose:
        s_f.show()
        print(sd.tls_ctx)

    # Send an HTTP request and get a response.
    req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ok = "HTTP/1.1 200 OK"
    resp = send_recv(sd, TLSPlaintext(data=req), rto)
    r = resp.haslayer(TLSRecord) and resp[TLSRecord].data.startswith(ok)
    if verbose:
        print("==> Got response from server")
        resp.show()
        if r:
            print("\n=== PASSED ===\n")
        else:
            print("\n=== FAILED ===\n")

    sd.close()
    return r
