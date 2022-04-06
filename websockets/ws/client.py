#! /usr/bin/python3

from random import randint
from threading import Thread
import datetime
import asyncio
import websockets
import time
import ssl


host = "localhost"
target_count = 1000


async def ws_ping_test(port):
    print("Start ping_test")
    count = 0
    ping_message = "ping_test"
    while True:
        async with websockets.connect(f"ws://{host}:{port}") as websocket:
            await websocket.send(ping_message)
            resp = await websocket.recv()
            if resp == "exit":
                break
            if ping_message == resp:
                count += 1
            if count >= target_count:
                print(f"{count}/{target_count} reached")
                ping_message = "exit"


async def wss_ping_test(port):
    print("Start wss_ping_test")
    count = 0
    ping_message = "ping_test"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations("/tmp/cert.pem")
    while True:
        async with websockets.connect(f"wss://{host}:{port}", ssl=ssl_context) as websocket:
            await websocket.send(ping_message)
            # resp = await websocket.recv()
            # if resp == "exit":
            #     break
            # if ping_message == resp:
            #     count += 1
            if count >= target_count:
                print(f"{count}/{target_count} reached")
                ping_message = "exit"


def run_ws_ping_test(port):
    time.sleep(1)
    print("run ws_ping_test")
    asyncio.run(ws_ping_test(port))
    print("success ws_ping_test")


def run_wss_ping_test(port):
    time.sleep(1)
    print("run wss_ping_test")
    asyncio.run(wss_ping_test(port))
    print("success wss_ping_test")


async def run_stress(port):
    print("run_stress")
    target_count = 1000
    count = 0
    ping_message = "ping_test"
    while True:
        # print(count)
        count += 1
        timeout_ = randint(9, 10)
        async with websockets.connect(f"ws://{host}:{port}", timeout=timeout_) as websocket:
            await websocket.send(ping_message)
            # resp = await websocket.recv()
            # if resp == "exit":
            #     pass
            # if ping_message == resp:
            #     count += 1
            if count >= target_count:
                return 0


async def threaded_stress(i, port):
    tasks = []
    for _ in range(i):
        tasks.append(run_stress(port))
    await asyncio.gather(*tasks, return_exceptions=True)
    return 0


def run():
    time.sleep(1)
    run_ws_ping_test(9080)
    run_wss_ping_test(9081)
    run_wss_ping_test(9082)
    try:
        run_wss_ping_test(9999)
    except Exception:
        print("Send exit_handler")
    finally:
        print("Exited")


if __name__ == "__main__":
    time.sleep(1)
    # run_ws_ping_test(9080)
    # run_wss_ping_test(9081)
    # run_wss_ping_test(9082)
    # run_wss_ping_test(9999)
    time_start = datetime.datetime.now()
    asyncio.run(threaded_stress(4, 8099))
    delta = datetime.datetime.now() - time_start
    print(delta)
