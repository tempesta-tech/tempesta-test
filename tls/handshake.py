from time import sleep
import scapy.layers.tls.crypto.suites as suites
from scapy.all import *
from scapy.layers.tls.all import *
from helpers import tf_cfg
from helpers.error import Error

def x509_check_issuer(cert, issuer):
    """
    The same as above, but for Issuer OrganizationName (O, OID '2.5.4.10').
    """
    for f in cert.tbsCertificate.issuer:
        if f.rdn[0].type.val == '2.5.4.10':
            return bytes(f.rdn[0].value).decode().endswith(issuer)
    raise Error("Certificate has no Issuer OrganizationName")


class ModifiedTLSClientAutomaton(TLSClientAutomaton):
    
    def __init__(self, *args, **kwargs):
        self.server_cert = None
        self.hs_state = False
        self.hs_final = False
        self.hs_buffer = []
        TLSClientAutomaton.__init__(self, *args, **kwargs)
    
    def _do_start(self, *args, **kargs):
        # type: (Any, Any) -> None
        ready = threading.Event()
        self.control_thread = threading.Thread(
            target=self._do_control,
            args=(ready,) + (args),
            kwargs=kargs,
            name="scapy.automaton _do_start"
        )
        self.control_thread.daemon = True
        self.control_thread.start()
        ready.wait()
    
    @ATMT.state()
    def RECEIVED_SERVERFLIGHT1(self):
        pass
    
    @ATMT.state()
    def TLSALERT_RECIEVED(self):
        self.vprint("Recieve TLSAlert from the server...")
        self.hs_state = False
        raise TLSAlert
        raise self.CLOSE_NOTIFY()
    
    @ATMT.condition(RECEIVED_SERVERFLIGHT1, prio=1)
    def should_handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        # Catch TLSAlert intead of TLSServerHello
        self.raise_on_packet(TLSAlert,
                             self.TLSALERT_RECIEVED)
        self.raise_on_packet(TLSServerHello,
                             self.HANDLED_SERVERHELLO)
    
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
    def RECEIVED_SERVERDATA(self):
        pass

    @ATMT.condition(RECEIVED_SERVERDATA, prio=1)
    def should_handle_ServerData(self):
        if not self.buffer_in:
            raise self.WAIT_CLIENTDATA()
        p = self.buffer_in[0]
        if isinstance(p, TLSApplicationData):
            if self.is_atmt_socket:
                # Socket mode
                self.oi.tls.send(p.data)
            else:
                tf_cfg.dbg(2, "> Received: %r" % p.data)
                self.hs_buffer.append(p)
        elif isinstance(p, TLSAlert):
            tf_cfg.dbg(2,"> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        elif isinstance(p, TLS13NewSessionTicket):
            tf_cfg.dbg(2, "> Received: %r " % p)
            # If arg session_ticket_file_out is set, we save
            # the ticket for resumption...
            if self.session_ticket_file_out:
                # Struct of ticket file :
                #  * ciphersuite_len (1 byte)
                #  * ciphersuite (ciphersuite_len bytes) :
                #       we need to the store the ciphersuite for resumption
                #  * ticket_nonce_len (1 byte)
                #  * ticket_nonce (ticket_nonce_len bytes) :
                #       we need to store the nonce to compute the PSK
                #       for resumption
                #  * ticket_age_len (2 bytes)
                #  * ticket_age (ticket_age_len bytes) :
                #       we need to store the time we received the ticket for
                #       computing the obfuscated_ticket_age when resuming
                #  * ticket_age_add_len (2 bytes)
                #  * ticket_age_add (ticket_age_add_len bytes) :
                #       we need to store the ticket_age_add value from the
                #       ticket to compute the obfuscated ticket age
                #  * ticket_len (2 bytes)
                #  * ticket (ticket_len bytes)
                with open(self.session_ticket_file_out, 'wb') as f:
                    f.write(struct.pack("B", 2))
                    # we choose wcs arbitrarily...
                    f.write(struct.pack("!H",
                                        self.cur_session.wcs.ciphersuite.val))
                    f.write(struct.pack("B", p.noncelen))
                    f.write(p.ticket_nonce)
                    f.write(struct.pack("!H", 4))
                    f.write(struct.pack("!I", int(time.time())))
                    f.write(struct.pack("!H", 4))
                    f.write(struct.pack("!I", p.ticket_age_add))
                    f.write(struct.pack("!H", p.ticketlen))
                    f.write(self.cur_session.client_session_ticket)
        else:
            tf_cfg.dbg(2, "> Received: %r" % p)
        self.buffer_in = self.buffer_in[1:]
        raise self.HANDLED_SERVERDATA()

    @ATMT.state()
    def CONNECT(self):
        s = socket.socket(self.remote_family, socket.SOCK_STREAM)
        tf_cfg.dbg(2, "Trying to connect on %s:%d" % (self.remote_ip,
                                                    self.remote_port))
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
        tf_cfg.dbg(1, "TLS handshake completed!")
        # self.vprint_sessioninfo()
        self.server_cert = self.cur_session.server_certs
        self.client_cert = self.cur_session.client_certs
        tf_cfg.dbg(2, "TLS handshake completed!")
        self.hs_state = True

class TlsHandshake:

    def __init__(self, data='GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n', debug=0):
        self.hs_state = False
        self.debug = debug
        self.sni = "tempesta-tech.com"
        self.host = self.sni
        self.data = data
        self.sign_algs = ['sha256+rsa', \
            'sha384+rsa', \
            'sha1+rsa', \
            'sha256+ecdsa', \
            'sha384+ecdsa', \
            'sha1+ecdsa', \
            'sha1+dsa', \
            'sha512+rsa', 'sha512+ecdsa'
            ]
        # Default extensions value
        self.ext_ec = TLS_Ext_SupportedEllipticCurves(groups=['x25519', 'secp256r1', 'secp384r1'])
        self.ext_sa = TLS_Ext_SignatureAlgorithms(sig_algs=self.sign_algs)
        self.renegotiation_info = TLS_Ext_RenegotiationInfo("")
        
    def create_hello(self):
        compression='null'
        # Override extension if some variables changd
        ext1 = TLS_Ext_ServerName(servernames=ServerName(servername=self.sni))
        ext2 = TLS_Ext_CSR(stype='ocsp', req=OCSPStatusRequest())
        ext4 = TLS_Ext_SupportedPointFormat(ecpl='uncompressed')
        ext6 = TLS_Ext_RenegotiationInfo("")
        # ext7 = TLS_Ext_SessionTicket(ticket)
        try:
            self.ciphers
            _ciphers = []
            for key in suites._tls_cipher_suites_cls:
                if key in self.ciphers:
                    tf_cfg.dbg(2, key, '->', suites._tls_cipher_suites_cls[key])
                    _ciphers += [suites._tls_cipher_suites_cls[key]]
            self.ciphers = _ciphers
        except KeyError:
            pass
        except AttributeError as e:
            tf_cfg.dbg(2, 'Use default ciphers')
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
        ext = [ext1, ext2, self.ext_ec, ext4, self.ext_sa, self.renegotiation_info]
        ch = TLSClientHello(gmt_unix_time=10000, ciphers=self.ciphers, ext=ext, comp=compression)
        tf_cfg.dbg(2, ch.show())
        return ch

    def do_12(self):
        c_h = self.create_hello()
        self.hs = ModifiedTLSClientAutomaton(
            client_hello=c_h, \
            server="127.0.0.1", \
            dport=443, \
            data=self.data, \
            debug=self.debug
            )
        self.hs.run(wait=False)
        self.hs.control_thread.join(5)
        tf_cfg.dbg(2, f'FIN_STATE: {self.hs.state.state}')
        tf_cfg.dbg(2, f'BUFFER: {self.hs.hs_buffer}')
        return self.hs.hs_state

# t = TlsHandshake()
# t.sni = ''
# t.ciphers = list(range(100, 49196))
# t.ciphers = list(range(100, 49196))
# t.do_12()
# sleep(2)
