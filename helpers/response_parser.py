"""
Module to parse curl-like response.

It is very simple implementation.
We can upgrade it if it needed.
"""
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


def parse_response(string_to_parse: Union[str, bytes]) -> Response:
    """
    Parse curl-like response string to dictionary.

    Args:
        string_to_parse (Union[str, bytes]): source string to parse

    Returns:
        response (Response): parsed response

    """
    headers = {}
    if isinstance(string_to_parse, bytes):
        string_to_parse = string_to_parse.decode()
    string_to_parse = string_to_parse.split('\r\n')

    # we expect first line such 'HTTP/1.1 200 OK'
    try:
        first_line = string_to_parse[0].split()
    except Exception as exc:
        return Response(error=str(exc))

    # next lines we expect as list of headers split by semicolon
    for line in string_to_parse[1:]:
        if line:
            line = line.split(':')
            headers[line[0].strip()] = line[1].strip()

    return Response(
        http_version=first_line[0],
        status=first_line[1],
        headers=headers,
    )
