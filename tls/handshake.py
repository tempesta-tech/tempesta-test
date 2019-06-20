# Basic TLS 1.2 handshake test.
#
# Also usable as a TLS traffic generator to debug early TLS server
# implementation. This tool emphasises flexibility in generation of TLS traffic,
# not performance.
#
# ScaPy is still not fully compatible with Python3, but I still use __future__
# module for easier migration to Python3.
# https://github.com/tintinweb/scapy-ssl_tls/issues/39
#
# TLS 1.2 is specified in RFC 5246. See also these useful references:
#   - https://wiki.osdev.org/SSL/TLS
#   - https://wiki.osdev.org/TLS_Handshake
#   - https://wiki.osdev.org/TLS_Encryption

from __future__ import print_function
import random
import socket
import struct
import scapy_ssl_tls.ssl_tls as tls

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def conn_estab(addr, port, rto):
    sock = tls.TLSSocket(socket.socket(), client=True)
    # Set large enough send and receive timeouts which will be used by default.
    sock.settimeout(rto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                    struct.pack('ll', 2, rto * 1000))
    sock.connect((addr, port))
    return sock


def send_recv(sock, pkt, rto):
    """
    Mainly a copy&paste from tls_do_round_trip(), but uses custom timeout to
    be able to fully read all data from Tempesta in verbose debugging mode
    (serial console verbose logging may be extremely slow).
    """
    resp = tls.TLS()
    try:
        sock.sendall(pkt)
        resp = sock.recvall(timeout=rto)
        if resp.haslayer(tls.TLSAlert):
            alert = resp[tls.TLSAlert]
            if alert.level != tls.TLSAlertLevel.WARNING:
                level = tls.TLS_ALERT_LEVELS.get(alert.level, "unknown")
                desc = tls.TLS_ALERT_DESCRIPTIONS.get(alert.description,
                                                      "unknown description")
                raise tls.TLSProtocolError("%s alert returned by server: %s"
                                           % (level.upper(), desc.upper()),
                                           pkt, resp)
    except socket.error as sock_except:
        raise tls.TLSProtocolError(sock_except, pkt, resp)
    return resp


def static_rnd(begin, end):
    """ A replacement for random.randint() to return constant results. """
    return (begin + end) / 2


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
        sock = conn_estab(cfg['addr'], cfg['port'], rto)
    except socket.error:
        print("Cannot connect to " + cfg['addr'] + ":" + str(cfg['port'])
              + ": " + str(socket.error))
        return 2

    c_h = tls.TLSClientHello(
        gmt_unix_time=0x22222222,
        random_bytes='\x11' * 28,
        cipher_suites=[tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        compression_methods=[tls.TLSCompressionMethod.NULL],
        # EtM isn't supported - just try to negate an unsupported extension.
        extensions=[
            tls.TLSExtension(type=0x16), # Encrypt-then-MAC
            tls.TLSExtension() / tls.TLSExtECPointsFormat(),
            tls.TLSExtension() / tls.TLSExtSupportedGroups(),
            tls.TLSExtension() / tls.TLSExtSignatureAlgorithms()]
        )
    msg1 = tls.TLSRecord(version='TLS_1_2') / \
            tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / c_h])
    if verbose:
        msg1.show()

    # Send ClientHello and read ServerHello, ServerCertificate,
    # ServerKeyExchange, ServerHelloDone.
    resp = send_recv(sock, msg1, rto)
    if verbose:
        resp.show()

    # Send ClientKeyExchange, ChangeCipherSpec.
    # get_client_kex_data() -> get_client_ecdh_pubkey() -> make_keypair()
    # use random, so replace it with our mock.
    randint_save = random.randint
    random.randint = static_rnd
    cke_h = tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                          sock.tls_ctx.get_client_kex_data()])
    random.randint = randint_save
    msg1 = tls.TLSRecord(version='TLS_1_2') / cke_h
    msg2 = tls.TLSRecord(version='TLS_1_2') / tls.TLSChangeCipherSpec()
    if verbose:
        msg1.show()
        msg2.show()

    sock.sendall(tls.TLS.from_records([msg1, msg2]))
    # Now we can calculate the final session checksum, send ClientFinished,
    # and receive ServerFinished.
    cf_h = tls.TLSHandshakes(
        handshakes=[tls.TLSHandshake() /
                    tls.TLSFinished(data=sock.tls_ctx.get_verify_data())])
    msg1 = tls.TLSRecord(version='TLS_1_2') / cf_h
    if verbose:
        msg1.show()

    resp = send_recv(sock, msg1, rto)
    if verbose:
        resp.show()
        print(sock.tls_ctx)

    # Send an HTTP request and get a response.
    req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    resp = send_recv(sock, tls.TLSPlaintext(data=req), rto)
    res = resp.haslayer(tls.TLSRecord) \
            and resp[tls.TLSRecord].data.startswith("HTTP/1.1 200 OK")
    if verbose:
        print("==> Got response from server")
        resp.show()
        if res:
            print("\n=== PASSED ===\n")
        else:
            print("\n=== FAILED ===\n")

    sock.close()
    return res
