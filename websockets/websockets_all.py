#! /usr/bin/python3
from multiprocessing import Process


import ws.client as client
import ws.server as server


if __name__ == "__main__":
    p1 = Process(target=server.run)
    p2 = Process(target=client.run)
    p1.start()
    p2.start()
    p1.join()
    p2.join()
