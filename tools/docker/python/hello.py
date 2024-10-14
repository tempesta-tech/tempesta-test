import argparse
import logging
import os

from aiohttp import web

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())

argument_parser = argparse.ArgumentParser()
argument_parser.add_argument("--body", type=str, default="Hello", help="set a response body")
argument_parser.add_argument(
    "-H", "--headers", type=str, action="append", help='set a response header "name: value"'
)

arguments = argument_parser.parse_args()
headers = []
if arguments.headers:
    for header in arguments.headers:
        headers.append(header.split(": "))


async def hello(request):
    return web.Response(headers=headers, text=arguments.body)


app = web.Application()
app.add_routes([web.get("/", hello)])
web.run_app(app, port=8000)
