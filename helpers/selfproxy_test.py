from . import selfproxy
import sys
import select
import asyncore

def keypressed():
    i,o,e = select.select([sys.stdin],[],[],001)
    for s in i:
        if s == sys.stdin:
            return True
    return False

selfproxy.request_client_selfproxy(
listen_host = "localhost",
listen_port = selfproxy.CLIENT_MODE_PORT_REPLACE,
forward_host = "localhost",
forward_port = 8080,
segment_size = 0,
segment_gap = 0
)

while not keypressed():
    #i = 0
    asyncore.loop(count=100, timeout=0.010)

selfproxy.release_client_selfproxy()
asyncore.loop()
print("EXIT")

