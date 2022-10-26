"""
TLS Handshake Class: Based on TLSAutomaton
Use it to overrides and see what happens
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2020 Tempesta Technologies, Inc."
__license__ = "GPL2"

import ssl
import scapy.layers.tls.crypto.suites as suites

from scapy.all import *
from scapy.layers.tls.record import _TLSEncryptedContent
from scapy.layers.tls.all import *
from helpers import tf_cfg, dmesg
from helpers.error import Error


def x509_check_cn(cert, cn):
    """
    Decode x509 certificate in BER and check CommonName (CN, OID '2.5.4.3')
    against passed @cn value. ScaPy-TLS can not parse ASN1 from certificates
    generated by the cryptography library, so we can not use full string
    matching and have to use substring matching instead.
    """
    for f in cert.tbsCertificate.issuer:
        if f.rdn[0].type.val == "2.5.4.3":
            return bytes(f.rdn[0].value).decode().endswith(cn)
    raise Error("Certificate has no CommonName")


def x509_check_issuer(cert, issuer):
    """
    The same as above, but for Issuer OrganizationName (O, OID '2.5.4.10').
    """
    for f in cert.tbsCertificate.issuer:
        if f.rdn[0].type.val == "2.5.4.10":
            return bytes(f.rdn[0].value).decode().endswith(issuer)
    raise Error("Certificate has no Issuer OrganizationName")



class ModifiedTLSClientAutomaton(TLSClientAutomaton):
    def __init__(self, *args, **kwargs):
        for key, value in kwargs.items():
            if key == "chunk":
                self.chunk = value
                tf_cfg.dbg(3, f"{key} == {value}" )
        del kwargs["chunk"]
        self.send_data = []
        self.server_data = []
        self.hs_state = False
        self.hs_final = False
        self.session_ticket = None
        self.master_secret = None
        TLSClientAutomaton.__init__(self, *args, **kwargs)

    def set_data(self, _data):
        self.send_data = _data

    def _do_start(self, *args, **kargs):
        # type: (Any, Any) -> None
        ready = threading.Event()
        self.control_thread = threading.Thread(
            target=self._do_control,
            args=(ready,) + (args),
            kwargs=kargs,
            name="scapy.automaton _do_start",
        )
        self.control_thread.daemon = True
        self.control_thread.start()
        ready.wait()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT1(self):
        pass

    @ATMT.state()
    def TLSALERT_RECIEVED(self):
        tf_cfg.dbg(2, "Recieve TLSAlert from the server...")
        self.hs_state = False
        raise TLSAlert
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def TLSFINISHED_REC(self):
        tf_cfg.dbg(2, "Recieve TLSFinished...")
        self.hs_state = False
        tf_cfg.dbg(3, "\n\n!!!!!!!!!!!!!!!!!!!!!!!\n\n")

    @ATMT.condition(RECEIVED_SERVERFLIGHT1, prio=1)
    def should_handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        # Catch TLSAlert intead of TLSServerHello
        self.raise_on_packet(TLSAlert, self.TLSALERT_RECIEVED)
        self.raise_on_packet(TLSServerHello, self.HANDLED_SERVERHELLO)

    @ATMT.state()
    def WAITING_RECORDS(self):
        self.get_next_msg(0.3, 1)
        raise self.RECEIVED_RECORDS()

    @ATMT.state()
    def RECEIVED_RECORDS(self):
        pass

    @ATMT.state()
    def HANDLED_CHANGECIPHERSPEC_AFTER_TICKET(self, get_next_msg=False):
        s = self.cur_session
        s.client_session_ticket = self.session_ticket
        s.master_secret = self.master_secret
        # tf_cfg.dbg(2, self.cur_pkt.show2())

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC_AFTER_TICKET)
    def wait_Finished_afterticket(self):
        tf_cfg.dbg(3, "\n\nTRY TO GET TLSSERVERFINISHED\n\n")
        self.get_next_msg(0.3, 1)
        raise self.WAITING_RECORDS()
        self.raise_on_packet(TLSFinished, self.HANDLED_SERVERFINISHED)

    @ATMT.condition(RECEIVED_RECORDS, prio=1)
    def should_handle_ServerRecords(self):
        if not self.buffer_in:
            raise self.WAIT_CLIENTDATA()
        p = self.buffer_in[0]
        tf_cfg.dbg(3, type(p))
        if isinstance(p, _TLSEncryptedContent):
            tf_cfg.dbg(2, "_TLSEncryptedContent DETECTED")
            # self.cur_session.show2()
            tf_cfg.dbg(3, self.cur_session.master_secret)
        if isinstance(p, TLSChangeCipherSpec):
            self.raise_on_packet(
                TLSChangeCipherSpec, self.HANDLED_CHANGECIPHERSPEC_AFTER_TICKET
            )
        if isinstance(p, TLSApplicationData):
            if self.is_atmt_socket:
                # Socket mode
                self.oi.tls.send(p.data)
            else:
                tf_cfg.dbg(3, "> Received: %r" % p.data)
        elif isinstance(p, TLSAlert):
            tf_cfg.dbg(3, "> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        else:
            tf_cfg.dbg(3, "> Received: %r" % p)
        self.buffer_in = self.buffer_in[1:]
        raise self.WAITING_RECORDS()

    @ATMT.condition(TLSClientAutomaton.RECEIVED_SERVERDATA, prio=1)
    def should_handle_ServerData(self):
        if not self.buffer_in:
            raise self.WAIT_CLIENTDATA()
        p = self.buffer_in[0]
        if isinstance(p, TLSApplicationData):
            self.server_data.append(p)
            if self.is_atmt_socket:
                # Socket mode
                self.oi.tls.send(p.data)
            else:
                tf_cfg.dbg(2, "> Received: %r" % p.data)
        elif isinstance(p, TLSAlert):
            self.server_data.append(p)
            tf_cfg.dbg(2, "> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        else:
            tf_cfg.dbg(2, "> Received: %r" % p)
        self.buffer_in = self.buffer_in[1:]
        raise self.HANDLED_SERVERDATA()

    @ATMT.condition(TLSClientAutomaton.HANDLED_SERVERHELLO, prio=1)
    def should_handle_ServerCertificate(self):
        if not self.cur_session.prcs.key_exchange.anonymous:
            self.raise_on_packet(TLSCertificate, self.HANDLED_SERVERCERTIFICATE)
        raise self.WAITING_RECORDS()

    @ATMT.condition(TLSClientAutomaton.PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO()

    @ATMT.state(initial=True)
    def INITIAL(self):
        tf_cfg.dbg(2, "Starting TLS client automaton.")
        raise self.INIT_TLS_SESSION()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT2(self):
        pass

    @ATMT.state()
    def RECEIVED_TICKET(self):
        self.session_ticket = self.cur_pkt

    @ATMT.condition(RECEIVED_SERVERFLIGHT2, prio=2)
    def should_handle_SessionTicket(self):
        self.raise_on_packet(TLSNewSessionTicket, self.RECEIVED_TICKET)

    @ATMT.condition(RECEIVED_SERVERFLIGHT2)
    def should_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec, self.HANDLED_CHANGECIPHERSPEC)

    @ATMT.condition(RECEIVED_TICKET)
    def should_handle_ChangeCipherSpecAfterTicket(self):
        self.raise_on_packet(TLSChangeCipherSpec, self.HANDLED_CHANGECIPHERSPEC)

    @ATMT.state()
    def CLOSE_NOTIFY(self):
        if tf_cfg.v_level() > 1:
            self.vprint()
            self.vprint("Trying to send a TLSAlert to the server...")

    @ATMT.state(final=True)
    def FINAL(self):
        # We might call shutdown, but it may happen that the server
        # did not wait for us to shutdown after answering our data query.
        # self.socket.shutdown(1)
        tf_cfg.dbg(2, "Closing client socket...")
        self.socket.close()
        self.hs_final = True
        tf_cfg.dbg(2, "Ending TLS client automaton.")

    @ATMT.state()
    def WAIT_CLIENTDATA(self):
        if len(self.send_data) > 0:
            msg = self.send_data.pop(0)
            self.add_record()
            self.add_msg(msg)
            raise self.ADDED_CLIENTDATA()

    @ATMT.state()
    def ADDED_CLIENTDATA(self):
        pass

    @ATMT.state()
    def RECEIVED_SERVERDATA(self):
        pass

    def flush_records(self):

        """
        Send all buffered records and update the session accordingly.
        """
        if self.chunk is not None:
            tf_cfg.dbg(2, "Trying to send data by chunk")
            _s = b"".join(p.raw_stateful() for p in self.buffer_out)
            n = self.chunk
            for chunk in [_s[i : i + n] for i in range(0, len(_s), n)]:
                self.socket.send(chunk)
        else:
            s = b"".join(p.raw_stateful() for p in self.buffer_out)
            self.socket.send(s)
        self.buffer_out = []

    @ATMT.state()
    def HANDLED_SERVERDATA(self):
        self.master_secret = self.cur_session.master_secret
        raise self.WAIT_CLIENTDATA()

    @ATMT.state()
    def ADDED_CLIENTDATA(self):
        pass

    @ATMT.state()
    def CONNECT(self):
        s = socket.socket(self.remote_family, socket.SOCK_STREAM)
        tf_cfg.dbg(2, "Trying to connect on %s:%d" % (self.remote_ip, self.remote_port))
        s.connect((self.remote_ip, self.remote_port))
        self.socket = s
        self.local_ip, self.local_port = self.socket.getsockname()[:2]
        if self.cur_session.advertised_tls_version in [0x0200, 0x0002]:
            raise self.SSLv2_PREPARE_CLIENTHELLO()
        elif self.cur_session.advertised_tls_version >= 0x0304:
            raise self.TLS13_START()
        else:
            raise self.PREPARE_CLIENTFLIGHT1()

    @ATMT.state()
    def HANDLED_SERVERFINISHED(self):
        self.server_cert = self.cur_session.server_certs
        self.client_cert = self.cur_session.client_certs
        if tf_cfg.v_level() > 1:
            self.vprint_sessioninfo()
            tf_cfg.dbg(3, self.server_cert[0])
        tf_cfg.dbg(2, "TLS handshake completed!")
        self.hs_state = True


class TlsHandshake:
    def __init__(self, chunk=None, debug=(tf_cfg.v_level() - 1)):
        self.server = "127.0.0.1"
        self.hs_state = False
        self.debug = debug
        self.sni = "tempesta-tech.com"
        self.host = self.sni
        self.chunk = chunk
        self.send_data = None
        self.sign_algs = [
            "sha256+rsa",
            "sha384+rsa",
            "sha1+rsa",
            "sha256+ecdsa",
            "sha384+ecdsa",
            "sha1+ecdsa",
            "sha1+dsa",
            "sha512+rsa",
            "sha512+ecdsa",
        ]
        self.ticket_data = None
        # Default extensions value
        self.ext_ec = TLS_Ext_SupportedEllipticCurves(
            groups=["x25519", "secp256r1", "secp384r1"]
        )
        self.ext_sa = TLS_Ext_SignatureAlgorithms(sig_algs=self.sign_algs)
        self.renegotiation_info = TLS_Ext_RenegotiationInfo("")

    def create_hello(self, resumption=False):
        compression = "null"
        # Override extension if some variables changd
        ext1 = TLS_Ext_ServerName(servernames=ServerName(servername=self.sni))
        ext2 = TLS_Ext_CSR(stype="ocsp", req=OCSPStatusRequest())
        ext4 = TLS_Ext_SupportedPointFormat(ecpl="uncompressed")
        try:
            self.ciphers
            _ciphers = []
            for key in suites._tls_cipher_suites_cls:
                if key in self.ciphers:
                    tf_cfg.dbg(2, key, "->", suites._tls_cipher_suites_cls[key])
                    _ciphers += [suites._tls_cipher_suites_cls[key]]
            self.ciphers = _ciphers
        except KeyError:
            pass
        except AttributeError as e:
            tf_cfg.dbg(2, "Use default ciphers")
            self.ciphers = [TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]
            self.ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
            self.ciphers += [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384]
            self.ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
            self.ciphers += [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA]
            self.ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]
            self.ciphers += [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
        if resumption:
            self.ciphers = [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
        ext = [ext1, ext2, self.ext_ec, ext4, self.ext_sa, self.renegotiation_info]

        if self.ticket_data is not None:
            ticket = TLS_Ext_SessionTicket(ticket=self.ticket_data)
            ext.append(ticket)

        ch = TLSClientHello(
            gmt_unix_time=10000, ciphers=self.ciphers, ext=ext, comp=compression
        )
        if tf_cfg.v_level() > 1:
            ch.show()
        return ch

    def do_12_res(self, _master_secret, automaton=ModifiedTLSClientAutomaton):
        """ TLS Handshake Resumption

        Args:
            _master_secret (bytes): _description_
            automaton (_type_, optional): _description_. Defaults to ModifiedTLSClientAutomaton.

        Returns:
            _type_: _description_
        """
        c_h = self.create_hello(resumption=True)
        if self.send_data is None:
            self.send_data = [
                TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n")
            ]
        # tf_cfg.dbg(2, f'self.data={self.data}')
        self.hs = automaton(
            client_hello=c_h,
            server=self.server,
            dport=443,
            resumption_master_secret=_master_secret,
            session_ticket_file_out="/home/wh1te/ticketfile",
            chunk=self.chunk,
            debug=self.debug,
        )
        if self.send_data is not None:
            self.hs.set_data(self.send_data)
        self.hs.run(wait=False)
        self.hs.control_thread.join(5)
        self.hs.socket.close()
        return self.hs.hs_state

    def do_12(self, automaton=ModifiedTLSClientAutomaton):
        """ Full TLS v1.2 Handshake

        Args:
            automaton (ModifiedTLSClientAutomaton, optional):
            You can pass your own modified automaton. 
            Defaults to ModifiedTLSClientAutomaton.

        Returns:
            bool: Handshake result
        """
        c_h = self.create_hello()
        if self.send_data is None:
            self.send_data = [
                TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n")
            ]

        self.hs = automaton(
            client_hello=c_h,
            server=self.server,
            dport=443,
            chunk=self.chunk,
            debug=self.debug,
        )
        if self.send_data is not None:
            self.hs.set_data(self.send_data)
        self.hs.run(wait=False)
        self.hs.control_thread.join(5)
        tf_cfg.dbg(2, f"Fin_state: {self.hs.state.state}")
        tf_cfg.dbg(2, f"Server_data: {self.hs.server_data}")
        tf_cfg.dbg(2, f"Session_ticket: {type(self.hs.session_ticket)}")
        self.hs.socket.close()
        return self.hs.hs_state



class TlsHandshakeStandard:
    """
    This class uses OpenSSL backend, so all its routines less customizable,
    but are good to test TempestaTLS behavior with standard tools and libs.
    """

    def __init__(self, addr=None, port=443, io_to=0.5, verbose=False):
        if addr:
            self.addr = addr
        else:
            self.addr = tf_cfg.cfg.get("Tempesta", "ip")
        self.port = port
        self.io_to = io_to
        self.verbose = verbose

    def try_tls_vers(self, version):
        klog = dmesg.DmesgFinder(ratelimited=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.io_to)
        sock.connect((self.addr, self.port))
        try:
            context = ssl.SSLContext(protocol=version)
            tls_sock = context.wrap_socket(sock)
        except ssl.SSLError as e:
            # Correct connection termination with PROTOCOL_VERSION alert.
            # if e.reason == "TLSV1_ALERT_PROTOCOL_VERSION":
            return True
        except IOError as e:
            if self.verbose:
                tf_cfg.dbg(3, "TLS handshake failed w/o warning")
        if self.verbose:
            tf_cfg.dbg(3, "Connection of unsupported TLS 1.%d established" % version)
        return False

    def do_old(self):
        """
        Test TLS 1.0 and TLS 1.1 handshakes.
        Modern OpenSSL versions don't support SSLv{1,2,3}.0, so use TLSv1.{0,1}
        just to test that we correctly drop wrong TLS connections. We do not
        support SSL as well and any SSL record is treated as a broken TLS
        record, so fuzzing of normal TLS fields should be used to test TLS
        fields processing.
        """
        for version in (ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1):
            if not self.try_tls_vers(version):
                return False
        return True
