"""
Module to parse curl-like response.

It is very simple implementation.
We can upgrade it if it needed.
"""
import re

from typing import Union, Optional


class Response(object):

    def __init__(
        self,
        http_version: str = '',
        status: Optional[Union[str, int]] = None,
        headers: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        super().__init__()
        self.http_version = http_version
        self.status = int(status)
        self.headers = headers if headers else {}
        self.error = error if error else ''

    def __repr__(self):
        return '{0} {1};\nHeaders: {2}\nErrors: {3}'.format(
            self.http_version,
            self.status,
            self.headers,
            self.error,
        )


def parse_response(raw_response: tuple, encoding='utf-8') -> Response:
    """
    Parse curl-like response string to dictionary.

    Curl response is returned as tuple.

    Args:
        raw_response (Union[str, bytes]): source string to parse

    Returns:
        response (Response): parsed response
    """
    headers = {}

    # check where is response raw data, it can be as first element (success
    # response) or second element (response with error)
    if raw_response[0]:
        raw_response = raw_response[0]

        raw_response = raw_response.decode(encoding)

        raw_response = raw_response.split('\r\n')

        # we expect first line such 'HTTP/1.1 200 OK'
        try:
            first_line = raw_response[0].split()
        except Exception as exc:
            return Response(error=str(exc))

        # next lines we expect as list of headers split by semicolon
        for line in raw_response[1:]:
            if line:
                line = line.split(':')
                headers[line[0].strip()] = line[1].strip()

        return Response(
            http_version=first_line[0],
            status=first_line[1],
            headers=headers,
        )

    # error case
    elif raw_response[1]:
        raw_response = raw_response[1]

        raw_response = raw_response.decode(encoding)
        re_match = re.search(r'error:\s(\d\d\d)', raw_response)

        return Response(
            status=re_match.group(1),
            error=raw_response,
        )
