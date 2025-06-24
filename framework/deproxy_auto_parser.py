__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import copy
import logging
import re
import sys

import run_config
from framework.deproxy_client import BaseDeproxyClient, DeproxyClient, DeproxyClientH2
from framework.deproxy_manager import DeproxyManager
from helpers.deproxy import (
    H2Request,
    H2Response,
    HttpMessage,
    ParseError,
    Request,
    Response,
)
from helpers.tempesta import Config


class DeproxyAutoParser:
    """
    This class prepares and checks HTTP responses/requests for deproxy.
    All functionality is called inside deproxy server/client automatically.
    Auto parser works in deproxy manager's thread.

    The main tasks - check all HTTP messages between deproxy server and client because
    Tempesta may damage message when forwarding.

    Please do not create class objects in tests!!!
    """

    def __init__(self, deproxy_manager: DeproxyManager, tempesta_config: Config):
        self.__deproxy_manager: DeproxyManager = deproxy_manager
        self.__expected_response: Response | None = None
        self.__expected_request: Request | None = None
        self.__client_request: Request | H2Request | None = None
        self.__parsing: bool = run_config.AUTO_PARSER
        self.__exceptions: list[AssertionError] = list()
        self.__tempesta_config: Config = tempesta_config
        self.__logger = logging.LoggerAdapter(
            logging.getLogger("dap"), extra={"service": f"{self.__class__.__name__}()"}
        )

    def cleanup(self) -> None:
        self.__parsing = run_config.AUTO_PARSER
        self.__expected_response = None
        self.__expected_request = None
        self.__client_request = None
        self.__exceptions = list()

    def check_exceptions(self) -> None:
        for exception in self.__exceptions:
            raise exception

    @property
    def parsing(self) -> bool:
        return self.__parsing

    @parsing.setter
    def parsing(self, parsing: bool) -> None:
        self.__parsing = parsing

    @property
    def __cache_on_tempesta(self) -> bool:
        matches = re.search(r"cache ([012]);", self.__tempesta_config.get_config())
        return bool(int(matches.group(1)[0]) if matches else 0)

    def check_expected_request(self, request: Request) -> None:
        if self.__expected_request is not None:
            self.__logger.info("Check expected request.")
            self.__logger.debug(f"Received request:\n{request.msg}")
            self.__logger.debug(f"Expected request:\n{self.__expected_request.msg}")
            try:
                assert request == self.__expected_request
            except AssertionError:
                self.__exceptions.append(sys.exc_info()[1])
            self.__logger.info("Received request is valid.")
        else:
            self.__logger.info(
                "Received request is not checked because the conditions were not satisfied."
            )

    def check_expected_response(self, response: Response | H2Response, is_http2: bool) -> None:
        """
        This method does not check response when:
            - there is no 2xx status code in the response. They are difficult to predict.
            - client request method is "PURGE". Tempesta responds with a default 200 response to
              such request.
            - client send request as bytes and parser does not have a client request
        """
        if (
            200 <= int(response.status) < 300
            and self.__expected_response
            and self.__client_request is not None
            and self.__client_request.method != "PURGE"
        ):
            self.__logger.info("Check expected response")
            expected_response = self.__prepare_expected_response_for_request(response, is_http2)

            self.__logger.debug(f"Received response:\n{response.msg}")
            self.__logger.debug(f"Expected response:\n{expected_response.msg}")

            try:
                assert response == expected_response
            except AssertionError:
                self.__exceptions.append(sys.exc_info()[1])
            self.__logger.info("Received response is valid.")
        else:
            self.__logger.info(
                "Received response is not checked because the expected response was not generated."
            )

    def prepare_expected_request(self, request: bytes, client: BaseDeproxyClient) -> None:
        self.__logger.info("Prepare expected request")
        self.__logger.debug(f"Request before preparing:\n{request.decode()}")

        try:
            request = Request(request.decode(), body_parsing=True)
        except (ParseError, ValueError):
            self.__logger.info("Request: invalid Content-Length header. Body parsing is disabled")
            request = Request(request.decode(), body_parsing=False)

        self.__client_request = copy.deepcopy(request)
        request.set_expected()
        request.add_tempesta_headers(x_forwarded_for=client.bind_addr or client.conn_addr)

        if not isinstance(client, DeproxyClientH2):
            request.headers.delete_all("trailer")

        self.__prepare_host_for_http1(request, isinstance(client, DeproxyClient))
        self.__prepare_hop_by_hop_headers(request)
        self.__prepare_method_for_expected_request(request)
        self.__expected_request = request

    def prepare_expected_response(self, response: bytes) -> None:
        """Prepare expected response from deproxy server."""
        self.__logger.info("Prepare expected response")
        self.__logger.debug(f"Response before preparing:\n{response.decode()}")

        try:
            response = Response(response.decode(), body_parsing=True)
        except (ValueError, ParseError):
            self.__logger.info("Response: invalid Content-Length header. Body prasing is disabled")
            response = Response(response.decode(), body_parsing=False)
        response.set_expected()
        response.add_tempesta_headers()
        response.headers.expected_time_delta = 20
        self.__expected_response = response

    def __prepare_expected_response_for_request(
        self, received_response: Response | H2Response, http2: bool
    ) -> Response | H2Response:
        """
        We prepare the expected response a second time when the client receives the response
        from Tempesta because deproxy server does not know about client protocol and the response
        maybe from cache.
        """
        if http2:
            expected_response = H2Response.convert_http1_to_http2(self.__expected_response)
        else:
            expected_response = copy.deepcopy(self.__expected_response)

        self.__prepare_body_for_HEAD_request(expected_response)

        expected_response.headers.delete_all("trailer")
        self.__prepare_hop_by_hop_headers(expected_response)

        is_cache = "age" in received_response.headers
        if is_cache:
            # Tempesta doesn't cache "set-cookie" header
            expected_response.headers.delete_all("set-cookie")
        if http2 or is_cache:
            self.__prepare_chunked_expected_response(expected_response, http2)
        else:
            if self.__client_request.method == "HEAD":
                for name, value in expected_response.trailer.headers:
                    expected_response.trailer.delete_all(name)

        if not http2:
            self.__add_content_length_header_to_expected_response(expected_response)

        self.__prepare_body_for_HEAD_request(expected_response)
        return expected_response

    def __prepare_host_for_http1(self, request: Request, is_http1: bool) -> None:
        """
        TempestaFW removes the host from the absolute uri
        and changes the host header for HTTP/1.1.
        """
        if is_http1 and request.uri.startswith("http"):
            self.__logger.info(
                "HTTP/1.1 client has an absolute uri. TempestaFW removes the host from the "
                "uri and changes the `Host` header."
            )
            host, _, url = request.uri.split("://")[1].partition("/")
            request.uri = f"/{url}" if url else "/"
            request.headers["host"] = host.rpartition("@")[-1]

    def __prepare_method_for_expected_request(self, request: Request) -> None:
        """
        Tempesta changes request method from 'PURGE' to 'GET'.
        And changes 'HEAD' to 'GET' when cache is enabled.
        """
        if request.method == "PURGE" or (request.method == "HEAD" and self.__cache_on_tempesta):
            self.__logger.info(
                "Client request method is 'PURGE'. Expected request method is changed to 'GET'."
            )
            request.method = "GET"

    def __prepare_body_for_HEAD_request(self, response: Response | H2Response) -> None:
        """Tempesta doesn't return trailers for HEAD requests."""
        if self.__client_request.method == "HEAD":
            self.__logger.info(f"Request method is 'HEAD'. Remove body from expected response")
            response.body = ""
            for name in response.trailer.keys():
                response.trailer.delete_all(name)

    def __prepare_hop_by_hop_headers(self, message: HttpMessage) -> None:
        self.__logger.info("Remove hop-by-hop headers from expected response/request")
        # headers specified in the connection header are hop-by-hop headers
        is_chunked_msg = True if message.trailer.keys() else False
        connection = message.headers.get("connection")
        if connection:
            connection = connection.split(" ")
            for hdr in connection:
                message.trailer.delete_all(hdr.lower())

        message.headers.delete_all("connection")
        message.headers.delete_all("keep-alive")
        message.headers.delete_all("proxy-connection")
        message.headers.delete_all("upgrade")
        message.trailer.delete_all("connection")
        message.trailer.delete_all("keep-alive")
        message.trailer.delete_all("proxy-connection")
        message.trailer.delete_all("upgrade")
        if (
            not message.trailer.keys()
            and message.body[-4:] not in ("\r\n\r\n", "\n\n")
            and isinstance(message, (Response, Request))
            and is_chunked_msg
        ):
            # We must add CRLF to a response from TempestaFW if trailers contain only hbp headers
            # because this response has no trailer part
            message.body += "\r\n"

    def __prepare_chunked_expected_response(
        self, expected_response: Response | H2Response, http2: bool
    ) -> None:
        """
        For http2:
            - Tempesta convert Transfer-Encoding header to Content-Encoding
        For cache response:
            - Tempesta store response with Content-Encoding and Content-length headers
        """
        method_is_head = self.__client_request.method == "HEAD"
        if "Transfer-Encoding" in expected_response.headers:
            self.__logger.info("Response: Transfer-Encoding header is present in http2/cache.")

            if http2:
                te = expected_response.headers.get("Transfer-Encoding")
                ce = ",".join(te.split(", ")[:-1])
                expected_response.headers.delete_all("Transfer-Encoding")
                if ce:
                    self.__logger.info(
                        "Response: Transfer-Encoding header convert to Content-Encoding"
                    )
                    expected_response.headers.add("content-encoding", ce)
            expected_response.convert_chunked_body(http2, method_is_head)

            # Tempesta FW remove trailers from response for HEAD request.
            if method_is_head:
                for name, value in expected_response.trailer.headers:
                    expected_response.trailer.delete_all(name)

    def __add_content_length_header_to_expected_response(
        self, expected_response: Response | H2Response
    ) -> None:
        if (
            expected_response.headers.get("content-length", None) is None
            and expected_response.status != "204"
            and expected_response.headers.get("Transfer-Encoding", None) is None
        ):
            self.__logger.info("Add Content-Length header to expected response.")
            expected_response.headers.add("content-length", str(len(expected_response.body)))

    def create_request_from_list_or_tuple(self, request: list | tuple) -> bytes:
        self.__logger.info("H2Request: convert to http1 request.")
        self.__logger.debug(f"H2Request: data before preparing:\n{request}")
        expected_request = Request()

        if isinstance(request, tuple):
            expected_request.body = request[1]
            headers = request[0]
        else:
            headers = request

        cookies = []
        for header in headers:
            if header[0] == ":authority":
                expected_request.headers.add(name="host", value=header[1])
            elif header[0] == ":path":
                expected_request.uri = header[1]
            elif header[0] == ":method":
                expected_request.method = header[1]
            elif header[0] == ":scheme":
                expected_request.version = "HTTP/1.1"
            elif header[0] == "cookie":
                cookies.append(header[1])
            else:
                expected_request.headers.add(name=header[0], value=header[1])

        hosts = list(expected_request.headers.find_all("host"))
        if len(hosts) > 1:
            self.__logger.info("H2Request: :authority and host headers are present.")
            expected_request.headers.delete_all("host")
            expected_request.headers["host"] = hosts[0]

        if cookies:
            self.__logger.info("H2Request: multiple cookie headers. Converted to one.")
            expected_request.headers.add("cookie", "; ".join(cookies))

        if expected_request.body:
            self.__logger.info("H2Request: has body. Added 'Content-Length' header")
            expected_request.headers.delete_all("content-length")
            expected_request.headers.add("content-length", len(expected_request.body))

        expected_request.build_message()
        return expected_request.msg.encode()
