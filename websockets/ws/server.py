#! /usr/bin/python3

import websockets
import asyncio
import ssl
import sys
import os
from OpenSSL import crypto
import subprocess


def cert_gen(
        emailAddress="emailAddress",
        commonName="localhost",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10*365*24*60*60,
        KEY_FILE="/tmp/key.pem",
        CERT_FILE="/tmp/cert.pem"):
    haproxy_pem = "/tmp/out.pem"
    out_files = []
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode("utf-8"))
        out_files.append(CERT_FILE)
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        out_files.append(KEY_FILE)
    filenames = [CERT_FILE, KEY_FILE]
    with open('/tmp/out.pem', 'w') as outfile:
        for fname in filenames:
            with open(fname) as infile:
                for line in infile:
                    outfile.write(line)
    out_files.append(haproxy_pem)
    return out_files


def remove_certs(cert_files_):
    for cert in cert_files_:
        os.remove(cert)


async def handler(websocket, path):
    data = await websocket.recv()
    reply = f"{data}"
    if data == "exit":
        await websocket.send(reply)
        print("Server_socket - Exit")
        await websocket.close()
    try:
        await websocket.send(reply)
    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected.  Do cleanup")
        await websocket.close()


async def secure_handler(websocket, path):
    data = await websocket.recv()
    reply = f"{data}"
    if data == "exit":
        await websocket.send(reply)
        print("Secure_server_socket - Exit")
        await websocket.close()
    try:
        await websocket.send(reply)
    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected.  Do cleanup")
        await websocket.close()


async def exit_handler(websocket, path):
    try:
        with await websocket.recv() as data:
            reply = f"{data}"
            print("Secure_server_socket - Exit")
            await websocket.close()
            asyncio.get_event_loop().stop()
            try:
                await websocket.send(reply)
            except websockets.exceptions.ConnectionClosed:
                print("Client disconnected.  Do cleanup")
                await websocket.close()
    except Exception:
        print("Exit handler recieved")
    finally:
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem', '/tmp/out.pem'])
        asyncio.get_event_loop().stop()


def exit_(code):
    sys.exit(code)


def servers_start(port):
    cert_gen()
    command = ['/usr/sbin/service', 'nginx', 'reload']
    code = subprocess.call(command, shell=False)
    print(f"Nginx reload code: {code}")
    command = ['/usr/sbin/service', 'haproxy', 'restart']
    code = subprocess.call(command, shell=False)
    print(f"Haproxy reload code: {code}")
    ssl._create_default_https_context = ssl._create_unverified_context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("/tmp/cert.pem", keyfile="/tmp/key.pem")
    ws_socket = websockets.serve(handler, "localhost", port)
    wss_socket = websockets.serve(
        secure_handler,
        "localhost",
        port+1,
        max_size=9000000,
        ssl=ssl_context,
    )
    wss_socket2 = websockets.serve(
        secure_handler,
        "localhost",
        port+2,
        max_size=9000000,
        ssl=ssl_context,
    )
    exit_socket = websockets.serve(
        exit_handler,
        "localhost",
        9999,
        max_size=9000000,
        ssl=ssl_context,
    )
    asyncio.get_event_loop().run_until_complete(ws_socket)
    asyncio.get_event_loop().run_until_complete(wss_socket)
    asyncio.get_event_loop().run_until_complete(wss_socket2)
    asyncio.get_event_loop().run_until_complete(exit_socket)
    asyncio.get_event_loop().run_forever()


def run():
    servers_start(8099)


if __name__ == "__main__":
    servers_start(8099)
