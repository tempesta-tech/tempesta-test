from time import sleep
import scapy.layers.tls.crypto.suites as suites
from scapy.all import *
from scapy.layers.tls.all import *
# from helpers import tf_cfg

class ModifiedTLSClientAutomaton(TLSClientAutomaton):
    
    def __init__(self, *args, **kwargs):
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
    
    @ATMT.condition(TLSClientAutomaton.PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO()

    @ATMT.state(final=True)
    def FINAL(self):
        # We might call shutdown, but it may happen that the server
        # did not wait for us to shutdown after answering our data query.
        # self.socket.shutdown(1)
        self.vprint("Closing client socket...")
        self.socket.close()
        self.hs_final = True
        self.vprint("Ending TLS client automaton.")

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
                print("> Received: %r" % p.data)
                print("add to hs_buffer")
                self.hs_buffer.append(p)
                print(f'BUFFER: {self.hs_buffer}')
        elif isinstance(p, TLSAlert):
            print("> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        elif isinstance(p, TLS13NewSessionTicket):
            print("> Received: %r " % p)
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
            print("> Received: %r" % p)
        self.buffer_in = self.buffer_in[1:]
        raise self.HANDLED_SERVERDATA()

    @ATMT.state()
    def HANDLED_SERVERFINISHED(self):
        self.vprint("TLS handshake completed!")
        self.vprint_sessioninfo()
        self.vprint("HANDLE SERVERFINISHED")
        print("TLS handshake completed!")
        print(self.hs_state)
        self.hs_state = True
        print(self.hs_state)

class TlsHandshake:

    def __init__(self, data='GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n', debug=2):
        self.hs_state = False
        self.data = data
        self.debug = debug
        self.sni = "tempesta-tech.com"

    def create_hello(self):
        global hs_state
        hs_state = False
        # TLS Version
        
        compression='null'
        ext1 = TLS_Ext_ServerName(servernames=ServerName(servername=self.sni))
        ext2 = TLS_Ext_CSR(stype='ocsp', req=OCSPStatusRequest())
        ext3 = TLS_Ext_SupportedEllipticCurves(groups=['x25519', 'secp256r1', 'secp384r1'])
        ext4 = TLS_Ext_SupportedPointFormat(ecpl='uncompressed')
        ext5 = TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsa', 'sha384+rsa', 'sha1+rsa', 'sha256+ecdsa', 'sha384+ecdsa', 'sha1+ecdsa', 'sha1+dsa', 'sha512+rsa', 'sha512+ecdsa'])
        ext6 = TLS_Ext_RenegotiationInfo("")
        # ext7 = TLS_Ext_SessionTicket(ticket)
        try:
            self.ciphers
            _ciphers = []
            for key in suites._tls_cipher_suites_cls:
                if key in self.ciphers:
                    # print(key, '->', suites._tls_cipher_suites_cls[key])
                    _ciphers += [suites._tls_cipher_suites_cls[key]]
            self.ciphers = _ciphers
        except KeyError:
            pass
        except AttributeError as e:
            print('Use default ciphers')
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
        ext = [ext1, ext2, ext3, ext4, ext5, ext6]
        ch = TLSClientHello(gmt_unix_time=10000, ciphers=self.ciphers, ext=ext, comp=compression)
        ch.show()
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
        print(self.hs.state.state)
        print(f'STATE: {self.hs.state.state}')
        print(f'BUFF: {self.hs.hs_buffer}')
        return self.hs.hs_state

# t = TlsHandshake()
# t.sni = ''
# t.ciphers = list(range(100, 49196))
# t.ciphers = list(range(100, 49196))
# print(t.do_12())
# print(t.do_12())
# sleep(2)
