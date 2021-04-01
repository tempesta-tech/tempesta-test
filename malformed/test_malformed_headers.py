from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class MalformedRequestsTest(tester.TempestaTest):
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : ('HTTP/1.1 200 OK\r\n'
                                  'Content-Length: 0\r\n'
                                  'Connection: keep-alive\r\n'
                                  '\r\n')
        },
    ]

    tempesta = {
        'config' : """
cache 0;
listen 80;

server ${general_ip}:8000;

""",
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
    ]

    def common_check(self, request):
        srv = self.get_server('deproxy')
        srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        clnt = self.get_client('deproxy')
        clnt.start()
        clnt.make_request(request)
        has_resp = clnt.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received")
        status = clnt.last_response.status
        self.assertEqual(int(status), 400, "Wrong status: %s" % status)

    def test_missing_name(self):
        # Header name must contain at least one token character to be valid.
        # Don't mix it up with http2 pseudo headers, starting with ':' since
        # SP after ':' is required.
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  ': invalid header\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_accept(self):
        # https://tools.ietf.org/html/rfc7231#section-5.3.2
        #
        # Accept = #( media-range [ accept-params ] )

        # media-range    = ( "*/*"
        #              / ( type "/" "*" )
        #              / ( type "/" subtype )
        #              ) *( OWS ";" OWS parameter )
        # accept-params  = weight *( accept-ext )
        # accept-ext = OWS ";" OWS token [ "=" ( token / quoted-string ) ]
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept: invalid\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_accept_charset(self):
        # https://tools.ietf.org/html/rfc7231#section-5.3.3
        # https://tools.ietf.org/html/rfc7231#section-3.1.1.2
        # https://tools.ietf.org/html/rfc6365#section-2
        #
        # Charset names ought to be registered in the IANA "Character Sets"
        # registry (<http://www.iana.org/assignments/character-sets>) according
        # to the procedures defined in [RFC2978].

        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Charset: invalid\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_accept_encoding(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.2.1
        #
        # All content-coding values are case-insensitive and ought to be
        # registered within the "HTTP Content Coding Registry", as defined in
        # Section 8.4.
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Encoding: invalid\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_accept_language(self):
        # https://tools.ietf.org/html/rfc4647#section-2.1
        #
        # language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"
        # alphanum         = ALPHA / DIGIT
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Language: 123456789\r\n' \
                  '\r\n'
        self.common_check(request)

    # Authorization
    # https://tools.ietf.org/html/rfc7235#section-4.2
    #
    # Authorization = credentials
    #
    # No format for credentials is defined

    def test_content_encoding(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.2.1
        # https://tools.ietf.org/html/rfc7231#section-8.4
        #
        # content-coding   = token
        #
        # All content-coding values are case-insensitive and ought to be
        # registered within the "HTTP Content Coding Registry", as defined in
        # Section 8.4.
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Encoding: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_content_language(self):
        # https://tools.ietf.org/html/rfc4647#section-2.1
        #
        # language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"
        # alphanum         = ALPHA / DIGIT
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Language: 123456789\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_content_length(self):
        # https://tools.ietf.org/html/rfc7230#section-3.3.2
        #
        # Content-Length = 1*DIGIT
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Length: not a number\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_content_location(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.4.2
        #
        # Content-Location = absolute-URI / partial-URI
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Location: not a uri\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_content_range(self):
        # https://tools.ietf.org/html/rfc7233#section-4.2
        #
        # Content-Range       = byte-content-range
        #                 / other-content-range
        #
        # byte-content-range  = bytes-unit SP
        #                   ( byte-range-resp / unsatisfied-range )
        #
        # byte-range-resp     = byte-range "/" ( complete-length / "*" )
        # byte-range          = first-byte-pos "-" last-byte-pos
        # unsatisfied-range   = "*/" complete-length
        #
        # complete-length     = 1*DIGIT
        #
        # other-content-range = other-range-unit SP other-range-resp
        # other-range-resp    = *CHAR
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Range: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_content_type(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.1.1
        #
        # media-type = type "/" subtype *( OWS ";" OWS parameter )
        # type       = token
        # subtype    = token
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Type: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_date(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
        #
        # "invalid" doesn't match neither current date format RFC5322
        # neither obsolete RFC850
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Date: invalid\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_expect1(self):
        # https://tools.ietf.org/html/rfc7231#section-5.1.1
        #
        # A server that receives an Expect field-value other than 100-continue
        # MAY respond with a 417 (Expectation Failed) status code to indicate
        # that the unexpected expectation cannot be met.
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Expect: invalid\r\n' \
                  '\r\n'
        srv = self.get_server('deproxy')
        srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        clnt = self.get_client('deproxy')
        clnt.start()
        clnt.make_request(request)
        resp = clnt.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        status = int(clnt.last_response.status)
        self.assertTrue(status == 417 or status == 200,
                        "Wrong status: %s" % status)

    def test_expect2(self):
        # https://tools.ietf.org/html/rfc7231#section-5.1.1
        #
        # A client MUST NOT generate a 100-continue expectation in a request
        # that does not include a message body.
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Expect: 100-continue\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_from(self):
        # https://tools.ietf.org/html/rfc5322#section-3.4
        # https://tools.ietf.org/html/rfc5322#section-3.4.1
        # https://tools.ietf.org/html/rfc7231#section-5.5.1
        #
        # "not a email" is not a email address
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'From: not a email\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_host(self):
        # https://tools.ietf.org/html/rfc7230#section-5.4
        #
        # Host = uri-host [ ":" port ] ; Section 2.7.1
        #
        # If the authority component is missing or
        # undefined for the target URI, then a client MUST send a Host header
        # field with an empty field-value.
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: http://\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_if_match(self):
        # https://tools.ietf.org/html/rfc7232#section-2.3
        # https://tools.ietf.org/html/rfc7232#section-3.1
        #
        # If-Match = "*" / 1#entity-tag
        # entity-tag = [ weak ] opaque-tag
        # weak       = %x57.2F ; "W/", case-sensitive
        # opaque-tag = DQUOTE *etagc DQUOTE
        # etagc      = %x21 / %x23-7E / obs-text
        # ; VCHAR except double quotes, plus obs-text
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Match: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_if_modified_since(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
        #
        # "invalid" is not a date
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Modified-Since: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_if_none_match(self):
        # https://tools.ietf.org/html/rfc7232#section-2.3
        # https://tools.ietf.org/html/rfc7232#section-3.2
        # Same as If-Match
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-None-Match: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_if_range(self):
        # https://tools.ietf.org/html/rfc7232#section-2.3
        # https://tools.ietf.org/html/rfc7232#section-3.5
        #
        # Same as If-Match
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Range: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_if_unmodified_since(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
        #
        # "invalid" is not a date
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Unmodified-Since: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_last_modified(self):
        # https://tools.ietf.org/html/rfc7232#section-2.2
        #
        # "invalid" is not a date
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Last-Modified: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_max_forwards(self):
        # https://tools.ietf.org/html/rfc7231#section-5.1.2
        #
        # Max-Forwards = 1*DIGIT
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Max-Forwards: not a number\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_pragma(self):
        # https://tools.ietf.org/html/rfc7231#section-5.1.2
        # https://tools.ietf.org/html/rfc1945#section-2.2
        #
        # Pragma           = 1#pragma-directive
        # pragma-directive = "no-cache" / extension-pragma
        # extension-pragma = token [ "=" ( token / quoted-string ) ]
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Pragma: not a token\r\n' \
                  '\r\n'
        self.common_check(request)


    # Proxy-Authorization
    # https://tools.ietf.org/html/rfc7235#section-4.4
    #
    # Proxy-Authorization = credentials

    def test_range(self):
        # https://tools.ietf.org/html/rfc7233#section-3.1
        #
        # Range = byte-ranges-specifier / other-ranges-specifier
        # other-ranges-specifier = other-range-unit "=" other-range-set
        # other-range-set = 1*VCHAR
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Range: invalid\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_referer(self):
        # https://tools.ietf.org/html/rfc7231#section-5.5.2
        #
        # Referer = absolute-URI / partial-URI
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Referer: not a uri\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_te(self):
        # https://tools.ietf.org/html/rfc7230#section-4.3
        #
        # TE        = #t-codings
        # t-codings = "trailers" / ( transfer-coding [ t-ranking ] )
        # t-ranking = OWS ";" OWS "q=" rank
        # rank      = ( "0" [ "." 0*3DIGIT ] )
        #            / ( "1" [ "." 0*3("0") ] )
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'TE: invalid te\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_trailer(self):
        # https://tools.ietf.org/html/rfc7230#section-4.4
        #
        # Trailer = 1#field-name
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Trailer: bad field name\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_transfer_encoding(self):
        # https://tools.ietf.org/html/rfc7230#section-4
        # https://tools.ietf.org/html/rfc7230#section-8.4
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # transfer-coding    = "chunked" ; Section 4.1
        #                / "compress" ; Section 4.2.1
        #                / "deflate" ; Section 4.2.2
        #                / "gzip" ; Section 4.2.3
        #                / transfer-extension
        # transfer-extension = token *( OWS ";" OWS transfer-parameter )
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Transfer-Encoding: not a token\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_upgrade(self):
        # https://tools.ietf.org/html/rfc7230#section-6.7
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # Upgrade          = 1#protocol
        #
        # protocol         = protocol-name ["/" protocol-version]
        # protocol-name    = token
        # protocol-version = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Upgrade: not a token\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_user_agent(self):
        # User-Agent
        # https://tools.ietf.org/html/rfc7231#section-5.5.3
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # User-Agent = product *( RWS ( product / comment ) )
        # product         = token ["/" product-version]
        # product-version = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'User-Agent: (bad user agent\r\n' \
                  '\r\n'
        self.common_check(request)

    def test_via(self):
        # https://tools.ietf.org/html/rfc7230#section-5.7.1
        # https://tools.ietf.org/html/rfc7230#section-6.7
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # Via = 1#( received-protocol RWS received-by [ RWS comment ] )
        #
        # received-protocol = [ protocol-name "/" ] protocol-version
        #                     ; see Section 6.7
        # received-by       = ( uri-host [ ":" port ] ) / pseudonym
        # pseudonym         = token
        #
        # protocol-version = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'User-Agent: (bad_protocol_version\r\n' \
                  '\r\n'
        self.common_check(request)

class MalformedResponsesTest(tester.TempestaTest):
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : ('HTTP/1.1 200 OK\r\n'
                                  'Content-Length: 0\r\n'
                                  '\r\n')
        },
    ]

    tempesta = {
        'config' : """
cache 0;
server ${general_ip}:8000;

""",
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
    ]

    request = 'GET / HTTP/1.1\r\n' \
              'Host: localhost\r\n' \
              '\r\n'

    def common_check(self, response, request, expect=502):
        srv = self.get_server('deproxy')
        srv.set_response(response)
        srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        clnt = self.get_client('deproxy')
        clnt.start()
        clnt.make_request(request)
        has_resp = clnt.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received")
        status = clnt.last_response.status
        self.assertEqual(int(status), expect, "Wrong status: %s" % status)

    def test_missing_name(self):
        # Header name must contain at least one token character to be valid.
        # Don't mix it up with http2 pseudo headers, starting with ':' since
        # SP after ':' is required.
        response = 'HTTP/1.1 200 OK\r\n' \
                   ': invalid header\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_accept_ranges(self):
        # https://tools.ietf.org/html/rfc7233#section-2.3
        # https://tools.ietf.org/html/rfc7233#section-2
        # https://tools.ietf.org/html/rfc7233#section-2.2
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # Accept-Ranges     = acceptable-ranges
        # acceptable-ranges = 1#range-unit / "none"
        #
        # An origin server that supports byte-range requests for a given target
        # resource MAY send
        #
        # Accept-Ranges: bytes
        #
        # A server that does not support any kind of range request for the
        # target resource MAY send
        #
        # Accept-Ranges: none
        #
        # range-unit       = bytes-unit / other-range-unit
        #
        # other-range-unit = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Accept-Ranges: invalid\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_age(self):
        # https://tools.ietf.org/html/rfc7234#section-5.1
        #
        # Age = delta-seconds
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Age: not a number\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_allow(self):
        # https://tools.ietf.org/html/rfc7230#section-3.1.1
        # https://tools.ietf.org/html/rfc7231#section-7.4.1
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # Allow = #method
        #
        # method = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Allow: (invalid\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # Alternates

    def test_cache_control1(self):
        # Cache-Control
        # https://tools.ietf.org/html/rfc7234#section-5.2
        #
        # Cache-Control   = 1#cache-directive
        #
        # cache-directive = token [ "=" ( token / quoted-string ) ]
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Cache-Control: not a token\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_cache_control2(self):
        # https://tools.ietf.org/html/rfc7234#section-5.2.1.1
        #
        #  Argument syntax:
        #    delta-seconds (see Section 1.2.1)
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Cache-Control: max-age=text\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_connection(self):
        # https://tools.ietf.org/html/rfc7230#section-6.1
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # Connection        = 1#connection-option
        # connection-option = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Connection: not a token\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_encoding(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.2.1
        # https://tools.ietf.org/html/rfc7231#section-8.4
        #
        # content-coding   = token
        #
        # All content-coding values are case-insensitive and ought to be
        # registered within the "HTTP Content Coding Registry", as defined in
        # Section 8.4.
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Encoding: invalid\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_language(self):
        # https://tools.ietf.org/html/rfc4647#section-2.1
        #
        # language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"
        # alphanum         = ALPHA / DIGIT
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Language: 123456789\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_length(self):
        # https://tools.ietf.org/html/rfc7230#section-3.3.2
        #
        # Content-Length = 1*DIGIT
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: not a number\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_location(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.4.2
        #
        # Content-Location = absolute-URI / partial-URI
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Location: not a uri\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_range(self):
        # https://tools.ietf.org/html/rfc7233#section-4.2
        #
        # Range = byte-ranges-specifier / other-ranges-specifier
        # other-ranges-specifier = other-range-unit "=" other-range-set
        # other-range-set = 1*VCHAR
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Range: invalid\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_type(self):
        # https://tools.ietf.org/html/rfc7231#section-3.1.1.1
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # media-type = type "/" subtype *( OWS ";" OWS parameter )
        # type       = token
        # subtype    = token
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Type: invalid\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_date(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
        #
        # "not a date" is invalid date
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Date: not a date\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_etag(self):
        # https://tools.ietf.org/html/rfc7232#section-2.3
        #
        # ETag       = entity-tag
        #
        # entity-tag = [ weak ] opaque-tag
        # weak       = %x57.2F ; "W/", case-sensitive
        # opaque-tag = DQUOTE *etagc DQUOTE
        # etagc      = %x21 / %x23-7E / obs-text
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Etag: not in quotes\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_expires(self):
        # https://tools.ietf.org/html/rfc7234#section-5.3
        #
        # "not a date" is a bad date
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Expires: not a date\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_last_modified(self):
        # https://tools.ietf.org/html/rfc7232#section-2.2
        #
        # "not a date" is a bad date
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Last-Modified: not a date\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_location(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.2
        # "not a uri" is a bad uri
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Location: not a uri\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # Proxy-Authenticate
    # https://tools.ietf.org/html/rfc7235#section-4.3
    # Proxy-Authenticate = 1#challenge

    def test_retry_after(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.3
        #
        # "not a date" is a bad date
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Retry-After: not a date\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_server(self):
        # https://tools.ietf.org/html/rfc7231#section-7.4.2
        #
        # Each product identifier consists of a name
        # and optional version, as defined in Section 5.5.3.
        #
        # https://tools.ietf.org/html/rfc7231#section-5.5.3
        #
        # product         = token ["/" product-version]
        # product-version = token
        #
        # https://tools.ietf.org/html/rfc7230#section-3.2.6
        #
        # token          = 1*tchar
        #
        # tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
        #                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        #                  / DIGIT / ALPHA
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Server: (bad_token\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_vary(self):
        # https://tools.ietf.org/html/rfc7231#section-7.1.4
        #
        # Vary = "*" / 1#field-name
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Vary: bad field\r\n' \
                   'Content-Length: 0\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # WWW-Authenticate
    # https://tools.ietf.org/html/rfc7235#section-4.1
    #
    # WWW-Authenticate = 1#challenge

class EtagAlphabetTest(tester.TempestaTest):
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : 'dummy'
        },
    ]

    tempesta = {
        'config' : """
cache 0;
listen 80;

server ${general_ip}:8000;

""",
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
    ]

    def common_check(self, response, resp_status):
        srv = self.get_server('deproxy')
        srv.set_response(response)
        srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        clnt = self.get_client('deproxy')
        clnt.start()
        clnt.make_request('GET / HTTP/1.1\r\n' \
                          'Host: localhost\r\n' \
                          '\r\n')
        has_resp = clnt.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received")
        status = clnt.last_response.status
        self.assertEqual(int(status), resp_status, "Wrong status: %s" % status)

    def test_etag_with_x00(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x000123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 502)

    def test_etag_with_x09(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x090123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 502)

    def test_etag_with_x20(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x200123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 502)

    def test_etag_with_x21(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x210123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 200)

    def test_etag_with_x22(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x220123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 502)

    def test_etag_with_x23(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x230123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 200)

    def test_etag_with_x7f(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x7f0123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 502)

    def test_etag_with_xf7(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\xf70123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 200)

class EtagAlphabetBrangeTest(EtagAlphabetTest):

    tempesta = {
        'config' : """
cache 0;
listen 80;

server ${general_ip}:8000;
http_etag_brange 0x09 0x20-0x21 0x23-0x7e 0x80-0xff;
""",
    }

    def test_etag_with_x09(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x090123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 200)

    def test_etag_with_x20(self):
        response = ('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Etag: W/\"\x200123456789\"\r\n'
                    '\r\n')
        self.common_check(response, 200)
