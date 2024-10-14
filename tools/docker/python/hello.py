import argparse
import logging
import os

from aiohttp import web

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())

argument_parser = argparse.ArgumentParser()
argument_parser.add_argument("--body", type=str, default="Hello", help="set a response body")

arguments = argument_parser.parse_args()


async def hello(request):
    return web.Response(text=arguments.body)


app = web.Application()
app.add_routes([web.get("/", hello)])
web.run_app(app, port=8000)
