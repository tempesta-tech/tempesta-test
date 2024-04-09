__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import copy
import sys

import run_config
from framework.deproxy_client import BaseDeproxyClient
from framework.deproxy_manager import DeproxyManager
from helpers.deproxy import (
    H2Request,
    H2Response,
    HttpMessage,
    ParseError,
    Request,
    Response,
)
from helpers.tf_cfg import dbg


class DeproxyAutoParser:
    """
    This class prepares and checks HTTP responses/requests for deproxy.
    All functionality is called inside deproxy server/client automatically.
    Auto parser works in deproxy manager's thread.

    The main tasks - check all HTTP messages between deproxy server and client because
    Tempesta may damage message when forwarding.

    Please do not create class objects in tests!!!
    """

    def __init__(self, deproxy_manager: DeproxyManager):
        self.__deproxy_manager: DeproxyManager = deproxy_manager
        self.__expected_response: Response | None = None
        self.__expected_request: Request | None = None
        self.__client_request: Request | H2Request | None = None
        self.__parsing: bool = run_config.AUTO_PARSER
        self.__dbg_msg = "\tDeproxy: AutoParser: {0}"
        self.__exceptions: list[AssertionError] = list()

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

    def check_expected_request(self, request: Request) -> None:
        if self.__expected_request is not None:
            dbg(4, self.__dbg_msg.format("Check expected request."))
            dbg(6, self.__dbg_msg.format(f"Received request:\n{request.msg}"))
            dbg(6, self.__dbg_msg.format(f"Expected request:\n{self.__expected_request.msg}"))
            try:
                assert request == self.__expected_request
            except AssertionError:
                self.__exceptions.append(sys.exc_info()[1])
            dbg(4, self.__dbg_msg.format("Received request is valid."))
        else:
            dbg(4, self.__dbg_msg.format("Request is not checked."))

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
            dbg(4, self.__dbg_msg.format("Check expected response"))
            expected_response = self.__prepare_expected_response_for_request(response, is_http2)

            dbg(6, self.__dbg_msg.format(f"Received response:\n{response.msg}"))
            dbg(6, self.__dbg_msg.format(f"Expected response:\n{expected_response.msg}"))

            try:
                assert response == expected_response
            except AssertionError:
                self.__exceptions.append(sys.exc_info()[1])
            dbg(4, self.__dbg_msg.format("Received response is valid."))
        else:
            dbg(4, self.__dbg_msg.format("Response is not checked."))

    def prepare_expected_request(self, request: bytes, client: BaseDeproxyClient) -> None:
        dbg(5, self.__dbg_msg.format("Prepare expected request"))
        dbg(6, self.__dbg_msg.format(f"Request before preparing:\n{request.decode()}"))

        try:
            request = Request(request.decode(), body_parsing=True)
        except (ParseError, ValueError):
            dbg(
                5,
                self.__dbg_msg.format(
                    "Request: invalid Content-Length header. Body parsing is disabled"
                ),
            )
            request = Request(request.decode(), body_parsing=False)

        self.__client_request = copy.deepcopy(request)
        request.set_expected()
        request.add_tempesta_headers(x_forwarded_for=client.bind_addr or client.conn_addr)
        self.__prepare_hop_by_hop_headers(request)

        self.__prepare_method_for_expected_request(request)

        self.__expected_request = request

    def prepare_expected_response(self, response: bytes) -> None:
        """Prepare expected response from deproxy server."""
        dbg(4, self.__dbg_msg.format("Prepare expected response"))
        dbg(6, self.__dbg_msg.format(f"Response before preparing:\n{response.decode()}"))

        try:
            response = Response(response.decode(), body_parsing=True)
        except (ValueError, ParseError):
            dbg(
                4,
                self.__dbg_msg.format(
                    "Response: invalid Content-Length header. Body prasing is disabled"
                ),
            )
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

        self.__prepare_hop_by_hop_headers(expected_response)

        is_cache = "age" in received_response.headers
        if http2 or is_cache:
            self.__prepare_chunked_expected_response(expected_response)

        if not http2 or is_cache:
            self.__add_content_length_header_to_expected_response(expected_response)

        return expected_response

    def __prepare_method_for_expected_request(self, request: Request) -> None:
        """Tempesta changes request method from 'PURGE' to 'GET'"""
        if request.method == "PURGE":
            dbg(
                4,
                self.__dbg_msg.format(
                    "Client request method is 'PURGE'. Expected request method is changed to 'GET'."
                ),
            )
            request.method = "GET"

    def __prepare_body_for_HEAD_request(self, response: Response | H2Response) -> None:
        if self.__client_request.method == "HEAD":
            dbg(
                4,
                self.__dbg_msg.format(
                    f"Request method is 'HEAD'. Remove body from expected response"
                ),
            )
            response.body = ""

    def __prepare_hop_by_hop_headers(self, message: HttpMessage) -> None:
        dbg(
            4,
            self.__dbg_msg.format("Remove hop-by-hop headers from expected response/request"),
        )
        message.headers.delete_all("connection")
        message.headers.delete_all("keep-alive")
        message.headers.delete_all("proxy-connection")
        message.headers.delete_all("upgrade")

    def __prepare_chunked_expected_response(self, expected_response: Response | H2Response) -> None:
        """
        For http2:
            - Tempesta convert Transfer-Encoding header to Content-Encoding
            - Tempesta moves trailers to headers
        For cache response:
            - Tempesta store response with Content-Encoding and Content-length headers
            - Tempesta moves trailers to headers
        """
        if "Transfer-Encoding" in expected_response.headers:
            dbg(
                4,
                self.__dbg_msg.format(
                    "Response: Transfer-Encoding header is present in http2/cache."
                ),
            )

            te = expected_response.headers.get("Transfer-Encoding")
            ce = ",".join(te.split(", ")[:-1])
            expected_response.headers.delete_all("Transfer-Encoding")
            if ce:
                dbg(
                    4,
                    self.__dbg_msg.format(
                        "Response: Transfer-Encoding header convert to Content-Encoding"
                    ),
                )
                expected_response.headers.add("content-encoding", ce)
            expected_response.convert_chunked_body()
            expected_response.headers.add("content-length", str(len(expected_response.body)))

            for name, value in expected_response.trailer.headers:
                dbg(4, self.__dbg_msg.format(f"Response: Trailer '{name}' moved to headers."))
                expected_response.trailer.delete_all(name)
                expected_response.headers.add(name, value)

    def __add_content_length_header_to_expected_response(
        self, expected_response: Response | H2Response
    ) -> None:
        if (
            expected_response.headers.get("content-length", None) is None
            and expected_response.status != "204"
            and expected_response.headers.get("Transfer-Encoding", None) is None
        ):
            dbg(4, self.__dbg_msg.format("Add Content-Length header to expected response."))
            expected_response.headers.add("content-length", str(len(expected_response.body)))

    def create_request_from_list_or_tuple(self, request: list | tuple) -> bytes:
        dbg(4, self.__dbg_msg.format("H2Request: convert to http1 request."))
        dbg(6, self.__dbg_msg.format(f"H2Request: data before preparing:\n{request}"))
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
            dbg(4, self.__dbg_msg.format("H2Request: :authority and host headers are present."))
            expected_request.headers.delete_all("host")
            expected_request.headers["host"] = hosts[0]

        if cookies:
            dbg(4, self.__dbg_msg.format("H2Request: multiple cookie headers. Converted to one."))
            expected_request.headers.add("cookie", "; ".join(cookies))

        if expected_request.body:
            dbg(4, self.__dbg_msg.format("H2Request: has body. Added 'Content-Length' header"))
            expected_request.headers.delete_all("content-length")
            expected_request.headers.add("content-length", len(expected_request.body))

        expected_request.build_message()
        return expected_request.msg.encode()
