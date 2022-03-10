#! /usr/bin/python3

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
            resp = await websocket.recv()
            if resp == "exit":
                break
            if ping_message == resp:
                count += 1
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


def run_stress(port):
    pass


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
    run_ws_ping_test(9080)
    run_wss_ping_test(9081)
    run_wss_ping_test(9082)
    run_wss_ping_test(9999)
