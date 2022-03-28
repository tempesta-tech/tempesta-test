"""
Test TLS tickets: Tempesta must handle both full and abbreviated handshakes.
"""

from framework import tester
from framework.x509 import CertGenerator
from helpers import remote, tf_cfg, util, dmesg
from .handshake import *


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TlsTicketTest(tester.TempestaTest):

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
            }
        """
    }

    def start_all(self):
        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")

    def test_no_ticket_support(self):
        """ Session ticket extension is not sent to the server, NewSessionTicket
        is not sent by Tempesta.
        """
        self.start_all()
        hs = TlsHandshake()
        hs.ticket_data = None
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_empty_ticket(self):
        """ Session ticket extension empty: client is waiting for the ticket,
        NewSessionTicket is sent by Tempesta. The same ticket can be used to
        establish TLS connection using abbreviated handshake.
        """
        ticket = ''
        master_secret = ''
        self.start_all()

        hs = TlsHandshake()
        hs.ticket_data = ''
        res = hs.do_12()
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)
        master_secret = getattr(hs.sock.tls_ctx, 'master_secret', None)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(ticket,
                             'Ticket value is empty, no NewSessionTicket message '
                             'was found')
        self.assertIsNotNone(master_secret,
                             "Can't read master secret")
        if not ticket:
            return
        self.assertEqual(len(ticket.ticket), 168)

        # A new connection with the same ticket will receive abbreviated
        # handshake
        hs_abb = TlsHandshake()
        hs_abb.set_ticket_data(ticket)
        res = hs_abb.do_12_resume(master_secret, ticket)
        ticket = getattr(hs_abb.sock.tls_ctx, 'ticket', None)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertNotEqual(ticket, None,
                            'Ticket value is empty, no NewSessionTicket message '
                            'was found')

    def test_invalid_ticket(self):
        """ Session ticket extension has invalid value, Tempesta rejects the
        ticket and falls back to the full handshake, and a
        NewSessionTicket message is received.
        """
        self.start_all()
        #random data is inserted, full handshake is processed
        t_random_data = 'asdfghjklqwertyuiozxcvbnmqwertyuiopasdfghjklzxcvbnm'
        hs = TlsHandshake()
        hs.set_ticket_data(t_random_data)
        hs.session_id = '\x38' * 32
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)
        self.assertIsNotNone(ticket,
                             'Ticket value is empty, no NewSessionTicket message '
                             'was found')
        self.assertNotEqual(ticket.ticket, '',
                            'Ticket value is empty, no NewSessionTicket message '
                            'was found')
        self.assertNotEqual(ticket.ticket, t_random_data,
                            'No new ticket was provided by Tempesta')

        # Now insert a modification into valid ticket data, ticket must be
        # rejected.
        t_data = ticket.ticket
        index = len(t_data) / 2
        repl = 'a' if t_data[index] != 'a' else 'b'
        t_data = t_data[:index] + repl + t_data[index + 1:]
        hs = TlsHandshake()
        hs.set_ticket_data(t_data)
        hs.session_id = '\x39' * 32
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)
        self.assertIsNotNone(ticket,
                             'Ticket value is empty, no NewSessionTicket message '
                             'was found')
        self.assertNotEqual(ticket.ticket, t_random_data,
                            'No new ticket was provided by Tempesta')


class TlsVhostConfusion(tester.TempestaTest):
    """Vhost confusion test: TLS session established with one vhost can't be
    resumed with another vhost.
    """

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'X-Vhost: tempesta-tech\r\n'
                'Connection: keep-alive\r\n\r\n'
        },
        {
            'id' : '1',
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'X-Vhost: tempesta\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    tempesta = {
        'custom_cert': True,
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            srv_group srv_grp2 {
                server ${server_ip}:8001;
            }

            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
                tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;
            }
            vhost tempesta.com {
                proxy_pass srv_grp2;
                tls_certificate ${tempesta_workdir}/tempesta.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.com.key;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "tempesta.com" -> tempesta.com;
                -> block;
            }
        """
    }

    @staticmethod
    def gen_certs(host_name):
        workdir = tf_cfg.cfg.get('Tempesta', 'workdir')
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        cgen.CN = host_name
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key())

    def start_all(self):
        self.gen_certs(u'tempesta-tech.com')
        self.gen_certs(u'tempesta.com')
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        for srv in [self.get_server('0'), self.get_server('1')]:
            self.assertTrue(srv.wait_for_connections(timeout=1),
                            "Cannot start Tempesta")

    def test(self):
        """ Session established with one vhost must not be resumed with
        another.
        """
        ticket = ''
        master_secret = ''
        self.start_all()

        # Obtain a working ticket first
        hs = TlsHandshake()
        hs.set_ticket_data('')
        hs.sni = ['tempesta-tech.com']
        res = hs.do_12()
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)
        master_secret = getattr(hs.sock.tls_ctx, 'master_secret', None)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(ticket,
                             'Ticket value is empty, no NewSessionTicket message '
                             'was found')
        self.assertIsNotNone(master_secret,
                             "Can't read master secret")
        if not ticket:
            return

        # A new connection with the same ticket will receive full, not
        # abbreviated, handshake because SNI is different.
        hs = TlsHandshake()
        hs.set_ticket_data(ticket)
        hs.session_id = '\x39' * 32
        hs.sni = ['tempesta.com']
        res = hs.do_12() # Full handshake, not abbreviated
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)


class TlsVhostConfusionDfltVhost(TlsVhostConfusion):

    tempesta = {
        'custom_cert': True,
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            srv_group default {
                server ${server_ip}:8001;
            }

            tls_certificate ${tempesta_workdir}/tempesta.com.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.com.key;

            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
                tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;
            }
            vhost default {
            # Vhost name is used in SNI parsing. Match all unknown SNIs to
            # default vhost.
                tls_match_any_server_name;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "tempesta.com" -> default;
                -> block;
            }
        """
    }


class TlsVhostConfusionDfltCerts(tester.TempestaTest):
    """ Vhosts are chosen by SNI, but global default certificates are used,
    thus vhost won't be confused.
    """

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'X-Vhost: tempesta-tech\r\n'
                'Connection: keep-alive\r\n\r\n'
        },
        {
            'id' : '1',
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'X-Vhost: tempesta\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    tempesta = {
        'custom_cert': True,
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            srv_group srv_grp2 {
                server ${server_ip}:8001;
            }

            tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;

            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            vhost tempesta.com {
                proxy_pass srv_grp1;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "tempesta.com" -> tempesta.com;
                -> block;
            }
        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        for srv in [self.get_server('0'), self.get_server('1')]:
            self.assertTrue(srv.wait_for_connections(timeout=1),
                            "Cannot start Tempesta")

    def test(self):
        """ Session established with one vhost must not be resumed with
        another.
        """
        ticket = ''
        master_secret = ''
        self.start_all()

        # Obtain a working ticket first
        hs = TlsHandshake()
        hs.set_ticket_data('')
        hs.sni = ['tempesta-tech.com']
        res = hs.do_12()
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)
        master_secret = getattr(hs.sock.tls_ctx, 'master_secret', None)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(ticket,
                             'Ticket value is empty, no NewSessionTicket message '
                             'was found')
        self.assertIsNotNone(master_secret,
                             "Can't read master secret")
        if not ticket:
            return

        # A new connection with the same ticket will receive full, not
        # abbreviated, handshake because SNI is different.
        hs = TlsHandshake()
        hs.set_ticket_data(ticket)
        hs.session_id = '\x39' * 32
        hs.sni = ['tempesta.com']
        # Abbreviated handshake with different SNI:
        res = hs.do_12() # Full handshake, not abbreviated
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = getattr(hs.sock.tls_ctx, 'ticket', None)


class TlsVhostConfusionDfltCertsWithUnknown(TlsVhostConfusionDfltCerts):
    """Tempesta can't chose vhost by SNI, but it still must not resume session
    with wrong sni value.
    """

    tempesta = {
        'custom_cert': True,
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            srv_group srv_grp2 {
                server ${server_ip}:8001;
            }

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;

            vhost vh1 {
                proxy_pass srv_grp1;
            }
            vhost vh2 {
                proxy_pass srv_grp2;
            }
            http_chain {
                host == "tempesta-tech.com" -> vh1;
                host == "tempesta.com" -> vh2;
                -> block;
            }
        """
    }


class StandardTlsClient(tester.TempestaTest):
    """Test against standard OpenSSL implementation. OpenSSL in python has no
    session resumption for clients, only session cache for servers. Strange
    since client sends empty SessionTicket extension and receives New Session
    Ticket, which is ignored.

    Curl also ignores TLS tickets. Have to use here tls-perf here.
    """

    clients = [
        {
            'id' : 'tls-perf',
            'type' : 'external',
            'binary' : 'tls-perf',
            'cmd_args' : (
                '-l 1 -t 1 -n 2  --tickets on ${server_ip} 443'
                )
        },
    ]

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
            }
        """
    }

    def test(self):
        tls_perf = self.get_client('tls-perf')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(tls_perf)
