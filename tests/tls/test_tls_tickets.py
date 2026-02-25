"""
Test TLS tickets: Tempesta must handle both full and abbreviated handshakes.
"""

from framework.helpers import remote
from framework.helpers.cert_generator_x509 import CertGenerator
from framework.test_suite import tester

from .handshake import *

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TlsTicketTest(tester.TempestaTest):
    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
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

    async def test_no_ticket_support(self):
        """Session ticket extension is not sent to the server, NewSessionTicket
        is not sent by Tempesta.
        """
        await self.start_all_services()
        hs = TlsHandshake()
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    async def test_empty_ticket(self):
        """Session ticket extension empty: client is waiting for the ticket,
        NewSessionTicket is sent by Tempesta. The same ticket can be used to
        establish TLS connection using abbreviated handshake.
        """
        ticket = ""
        master_secret = ""
        await self.start_all_services()
        hs = TlsHandshake()
        hs.ticket_data = ""
        res = hs.do_12()
        ticket = hs.hs.session_ticket.ticket
        cached_secrets = SessionSecrets(hs.hs.cur_session)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(ticket, "Ticket value is empty")
        self.assertIsNotNone(master_secret, "Can't read master secret")

        # # A new connection with the same ticket will receive abbreviated
        # # handshake

        hs_abb = TlsHandshake()
        hs_abb.ticket_data = ticket
        res = hs_abb.do_12_res(cached_secrets)
        # ticket = getattr(hs_abb.sock.tls_ctx, 'ticket', None)
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        # self.assertNotEqual(ticket, None,
        #                     'Ticket value is empty, no NewSessionTicket message '
        #                     'was found')

    async def test_invalid_ticket(self):
        """Session ticket extension has invalid value, Tempesta rejects the
        ticket and falls back to the full handshake, and a
        NewSessionTicket message is received.
        """
        await self.start_all_services()
        # random data is inserted, full handshake is processed
        t_random_data = "asdfghjklqwertyuiozxcvbnmqwertyuiopasdfghjklzxcvbnm"
        hs = TlsHandshake()
        hs.ticket_data = t_random_data
        hs.session_id = "\x38" * 32
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = hs.hs.session_ticket
        self.assertIsNotNone(
            ticket, "Ticket value is empty, no NewSessionTicket message " "was found"
        )
        self.assertNotEqual(
            ticket.ticket, "", "Ticket value is empty, no NewSessionTicket message " "was found"
        )
        self.assertNotEqual(ticket.ticket, t_random_data, "No new ticket was provided by Tempesta")

        # Now insert a modification into valid ticket data, ticket must be
        # rejected.
        t_data = ticket.ticket
        index = len(t_data) / 2
        repl = t_data[int(index)] + 1 if t_data[int(index)] < 255 else t_data[int(index)] - 1
        t_data = t_data[: int(index)] + chr(repl).encode() + t_data[int(index) + 1 :]
        hs = TlsHandshake()
        hs.ticket_data = t_data
        hs.session_id = "\x39" * 32
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        ticket = hs.hs.session_ticket
        self.assertIsNotNone(
            ticket, "Ticket value is empty, no NewSessionTicket message " "was found"
        )
        self.assertNotEqual(ticket.ticket, t_random_data, "No new ticket was provided by Tempesta")


class TlsVhostConfusion(tester.TempestaTest):
    """Vhost confusion test: TLS session established with one vhost can't be
    resumed with another vhost.
    """

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-Vhost: tempesta-tech\r\n"
            "Connection: keep-alive\r\n\r\n",
        },
        {
            "id": "1",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-Vhost: tempesta\r\n"
            "Connection: keep-alive\r\n\r\n",
        },
    ]

    tempesta = {
        "custom_cert": True,
        "config": """
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
        """,
    }

    @staticmethod
    def gen_certs(host_name):
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        cgen.CN = host_name
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    async def test(self):
        """Session established with one vhost must not be resumed with
        another.
        """
        self.gen_certs("tempesta-tech.com")
        self.gen_certs("tempesta.com")
        await self.start_all_services()

        # Obtain a working ticket first
        hs = TlsHandshake()
        hs.ticket_data = ""
        hs.sni = "tempesta-tech.com"
        res = hs.do_12()
        cached_secrets = SessionSecrets(hs.hs.cur_session)
        master_secret = hs.hs.master_secret
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(
            hs.hs.session_ticket, "Ticket value is empty, no NewSessionTicket was found"
        )
        self.assertIsNotNone(master_secret, "Can't read master secret")

        # A new connection with the same ticket will receive full, not
        # abbreviated, handshake because SNI is different.
        hs_abb = TlsHandshake()
        hs_abb.ticket_data = hs.hs.session_ticket.ticket
        hs_abb.sni = "tempesta.com"
        hs.send_data = []
        res = hs_abb.do_12_res(cached_secrets)  # Try abbreviated handshake
        self.assertTrue(hs_abb.hs.full_hs, "Abbreviated handshake detected")
        self.assertFalse(res, "Wrong handshake result")


class TlsVhostConfusionDfltVhost(TlsVhostConfusion):
    tempesta = {
        "custom_cert": True,
        "config": """
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
            # Vhost name is used in SNI parsing. Match all unknown SNIs to
            # default vhost.  
            tls_match_any_server_name;
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
                tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;
            }
            
            vhost default {proxy_pass default;}
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "tempesta.com" -> default;
                -> block;
            }
        """,
    }


class TlsVhostConfusionDfltCerts(tester.TempestaTest):
    """Vhosts are chosen by SNI, but global default certificates are used,
    thus vhost won't be confused.
    """

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-Vhost: tempesta-tech\r\n"
            "Connection: keep-alive\r\n\r\n",
        },
        {
            "id": "1",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-Vhost: tempesta\r\n"
            "Connection: keep-alive\r\n\r\n",
        },
    ]

    tempesta = {
        "custom_cert": True,
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            srv_group srv_grp2 {
                server ${server_ip}:8001;
            }

            vhost tempesta-tech.com {
                tls_certificate ${tempesta_workdir}/tempesta-tech.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta-tech.com.key;
                proxy_pass srv_grp1;
            }

            vhost tempesta.com {
                tls_certificate ${tempesta_workdir}/tempesta.com.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.com.key;
                proxy_pass srv_grp1;
            }
            
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "tempesta.com" -> tempesta.com;
                -> block;
            }
        """,
    }

    @staticmethod
    def gen_certs(host_name):
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        cgen.CN = host_name
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    async def test(self):
        """Session established with one vhost must not be resumed with
        another.
        """
        self.gen_certs("tempesta-tech.com")
        self.gen_certs("tempesta.com")
        await self.start_all_services()

        # Obtain a working ticket first
        hs = TlsHandshake()
        hs.ticket_data = ""
        hs.sni = "tempesta-tech.com"
        res = hs.do_12()
        cached_secrets = SessionSecrets(hs.hs.cur_session)
        ticket = hs.hs.session_ticket.ticket
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        self.assertIsNotNone(
            hs.hs.session_ticket, "Ticket value is empty, no NewSessionTicket recieved"
        )
        self.assertIsNotNone(cached_secrets.master_secret, "Can't read master secret")

        # A new connection with the same ticket will receive full, not
        # abbreviated, handshake because SNI is different.
        hs_abb = TlsHandshake()
        hs_abb.ticket_data = ticket
        hs_abb.sni = "tempesta.com"
        hs_abb.send_data = []
        res = hs_abb.do_12_res(cached_secrets)
        self.assertTrue(hs_abb.hs.full_hs, "Abbreviated handshake detected")
        self.assertFalse(res, "Wrong handshake result")


class TlsVhostConfusionDfltCertsWithUnknown(TlsVhostConfusionDfltCerts):
    """Tempesta can't chose vhost by SNI, but it still must not resume session
    with wrong sni value.
    """

    tempesta = {
        "custom_cert": True,
        "config": """
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
        """,
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
            "id": "tls-perf",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": ("-l 1 -t 1 -n 2  --tickets on ${tempesta_ip} 443"),
        },
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

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

    async def test(self):
        tls_perf = self.get_client("tls-perf")

        self.start_all_servers()
        await self.start_tempesta()
        tls_perf.start()
        await self.wait_while_busy(tls_perf)
        tls_perf.stop()
        self.assertFalse(tls_perf.stderr)
