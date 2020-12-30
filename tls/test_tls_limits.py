"""
Tests for Frang TLS limits.
"""

import time
from framework import tester
from helpers import remote, tf_cfg, util, dmesg


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TLSLimits(tester.TempestaTest):
    """Client is blocked if opens to many new TLS sessions.
    """

    clients = [
        {
            'id' : 'tls-perf',
            'type' : 'external',
            'binary' : 'tls-perf',
            'cmd_args' : (
                '-l 1 -t 1 -n 11  --tickets off ${server_ip} 443'
                )
        },
        {
            'id' : 'tls-perf-with-tickets',
            'type' : 'external',
            'binary' : 'tls-perf',
            'cmd_args' : (
                '-l 1 -t 1 -n 20  --tickets on ${server_ip} 443'
                )
        },
        {
            'id' : '0',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '1',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '5',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '6',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '7',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '8',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '9',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '10',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : '11',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
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

            frang_limits {
                tls_connection_rate 10;
            }
        """
    }

    TLS_WARN="Warning: frang: new TLS connections rate exceeded for "
    BURST = False

    def test_with_tlsperf(self):
        """
        Test with tls-perf which uses usual openssl configuration and works as
        most usual ssl clients. tls-perf doesn't have fixed frame rate, but it
        works fast and we use small limits to ensure that all messages are
        received almost immediately.
        """

        self.start_all_servers()
        self.start_tempesta()
        srv = self.get_server('0')
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))

        klog = dmesg.DmesgFinder(ratelimited=False)

        tls_perf = self.get_client('tls-perf-with-tickets')
        tls_perf.start()
        self.wait_while_busy(tls_perf)
        self.assertEqual(klog.warn_count(self.TLS_WARN), 0,
                         "Frang limits warning was incorrectly shown")

        tls_perf = self.get_client('tls-perf')
        tls_perf.start()
        self.wait_while_busy(tls_perf)
        self.assertEqual(klog.warn_count(self.TLS_WARN), 1,
                         "Frang limits warning is not shown")

    def test_with_deproxy(self):
        """ Test with deproxy, Python has no session resumption on client side,
        thus clients will use a new TLS session every time. If self.BURST is
        disabled, make a pause to open connections slower. Don't use high limit
        values here: deproxy is not fast.
        """
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(srv.wait_for_connections(timeout=1))

        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: tempesta-tech.com\r\n" \
                   "\r\n"
        connected = 0
        not_connected = 0
        for i in range(11):
            deproxy_cl = self.get_client('%d' %i)
            deproxy_cl.start()
            # Test works more stable if client sends a request
            deproxy_cl.make_requests(requests)
            deproxy_cl.wait_for_response()
            if not deproxy_cl.connection_is_closed():
                connected += 1
            else:
                not_connected += 1
            if i == 5 and not self.BURST:
                time.sleep(0.5)

        self.assertEqual(1, not_connected)
        self.assertEqual(10, connected)
        self.assertEqual(klog.warn_count(self.TLS_WARN), 1,
                          "Frang limits warning is not shown")


class TLSLimitsBurst(TLSLimits):

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

            frang_limits {
                tls_connection_burst 10;
                tls_connection_rate 20;
            }
        """
    }

    TLS_WARN="Warning: frang: new TLS connections burst exceeded for "
    BURST = True


class TLSLimitsIncomplete(tester.TempestaTest):
    """Client is blocked if it recently tried to open a few TLS sessions, none
    of them was successfully established.
    """

    clients = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '1',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '5',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '6',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '7',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '8',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '9',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '10',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : False,
        },
        {
            'id' : '11',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
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

            frang_limits {
                tls_incomplete_connection_rate 10;
            }
        """
    }

    TLS_WARN="Warning: frang: incomplete TLS connections rate exceeded"

    def test(self):
        """
        """

        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(srv.wait_for_connections(timeout=1))

        self.klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: tempesta-tech.com\r\n" \
                   "\r\n"
        connected = 0
        not_connected = 0
        for i in range(11):
            deproxy_cl = self.get_client('%d' %i)
            deproxy_cl.start()
            # Push some data as request, don't use make_requests() here to
            # avoid parsing errors on TLS alers
            deproxy_cl.request_buffers += requests
            # Give some time to process events.
            time.sleep(0.01)
            if not deproxy_cl.connection_is_closed():
                connected += 1
            else:
                not_connected += 1
            # Need to stop client or TLS warning is now shown until Tempesta
            # shutdown
            deproxy_cl.stop()

        self.assertEqual(0, connected)
        self.assertEqual(11, not_connected)
        wc = self.klog.warn_count(self.TLS_WARN)
        self.assertEqual(wc, 1, "Frang limits warning is not shown")


class TLSMatchHostSni(tester.TempestaTest):

    clients = [
        {
            'id' : 'usual-client',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
            'ssl_hostname' : 'tempesta-tech.com'
        },
        {
            'id' : 'no-sni-client',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl'  : True,
        },
        {
            'id' : 'over-444-port',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '444',
            'ssl'  : True,
            'ssl_hostname' : 'tempesta-tech.com'
        }
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
            listen 444 proto=https;

            frang_limits {
                http_host_required;
            }

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            # Any request can be served.
            http_chain {
                -> tempesta-tech.com;
            }
        """
    }

    TLS_WARN="Warning: frang: host header doesn't match SNI from TLS handshake"
    TLS_WARN_PORT="Warning: frang: port from host header doesn't match real port"

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(srv.wait_for_connections(timeout=1))

    def test_host_sni_mismatch(self):
        """ With the `http_host_required` limit, the host header and SNI name
        must be identical. Otherwise request will be filtered. After client
        send a request that doesnt match his SNI, t is blocked
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: tempesta-tech.com\r\n" \
                   "\r\n" \
                   "GET / HTTP/1.1\r\n" \
                   "Host:    tempesta-tech.com     \r\n" \
                   "\r\n" \
                   "GET / HTTP/1.1\r\n" \
                   "Host: example.com\r\n" \
                   "\r\n"
        deproxy_cl = self.get_client('usual-client')
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.TLS_WARN), 1,
                          "Frang limits warning is not shown")

    def test_host_sni_bypass_check(self):
        """ SNI is not set. Requests to any ports are allowed.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: example.com\r\n" \
                   "\r\n"
        deproxy_cl = self.get_client('no-sni-client')
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(1, len(deproxy_cl.responses))
        self.assertEqual(klog.warn_count(self.TLS_WARN), 0,
                          "Frang limits warning was unexpectedly shown")

    def test_port_mismatch(self):
        """ After client send a request that has port mismatch in host header,
        # it is blocked.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: tempesta-tech.com:80\r\n" \
                   "\r\n"
        deproxy_cl = self.get_client('usual-client')
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.TLS_WARN_PORT), 1,
                          "Frang limits warning is not shown")

    def test_auto_port_mismatch(self):
        """ After client send a request that has port mismatch in host header,
        # it is blocked. Port is defined from implicit values.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" \
                   "Host: tempesta-tech.com\r\n" \
                   "\r\n"
        deproxy_cl = self.get_client('over-444-port')
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.TLS_WARN_PORT), 1,
                          "Frang limits warning is not shown")
