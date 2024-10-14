import logging
import os

from aiohttp import web

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())


async def hello(request):
    return web.Response(text="Hello")


app = web.Application()
app.add_routes([web.get("/", hello)])
web.run_app(app, port=8000)
