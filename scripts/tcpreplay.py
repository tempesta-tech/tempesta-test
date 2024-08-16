__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


import json
import os
import subprocess as sp
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class HttpRequest:
    method: str
    uri: str
    version: str
    headers: list[tuple[str, str]]
    body: str | None


@dataclass
class HeadersFrame:
    stream_id: int
    headers: list[tuple[str, str]]
    flags: str


@dataclass
class DataFrame:
    stream_id: int
    body: bytes
    flags: str


@dataclass
class SettingsFrame:
    header_table_size: int | None = None
    enable_push: int | None = None
    initial_window_size: int | None = None
    max_frame_size: int | None = None
    max_concurrent_streams: int | None = None
    max_header_list_size: int | None = None


class HttpReader:
    """Read tcp packets from .pcap files and prepare HTTP requests."""

    def __init__(
        self,
        # Example command: tcpdump -U -i any host tempesta_ip -w file_path.pcap
        tcpdump_files: list[str] | None = None,
        # Example command: tshark -i any -T ek -J "tcp http2" -Y "http2" >> output
        tshark_files: list[str] | None = None,
        tempesta_tls_ports: tuple[str] = ("443",),
        tempesta_http_ports: tuple[str] = ("80",),
        output_suffix: str = "",
        home_dir: str = "",
    ):
        if tcpdump_files is None and tshark_files is None:
            raise AttributeError("You must set `tcpdump_files` or `tshark_files` args, or both.")
        self.__tcpdump_files: list[str] = tcpdump_files
        self.__tshark_files: list[str] = tshark_files
        self.__tempesta_tls_ports: tuple[str] = tempesta_tls_ports
        self.__tempesta_https_ports: tuple[str] = tempesta_http_ports
        self.__output_file: str = f"{home_dir}output{output_suffix}.json"
        self.__http2_file: str = f"{home_dir}http2_requests{output_suffix}.json"
        self.__https_file: str = f"{home_dir}https_requests{output_suffix}.json"
        self.__http_file: str = f"{home_dir}http_requests{output_suffix}.json"
        self.http2_requests: dict = defaultdict(dict)
        self.https_requests: dict = defaultdict(dict)
        self.http_requests: dict = defaultdict(dict)
        self.__remove_old_files()
        if self.__tcpdump_files:
            self.__extract_http_and_http2_packets()

    def prepare_http_messages(self) -> None:
        """Prepare h2, https, http requests for sending or saving to files."""
        files = self.__tshark_files
        if os.path.exists(self.__output_file):
            files.append(self.__output_file)

        for file_name in files:
            with open(file_name, "rb") as file:
                for line in file:
                    packet = json.loads(line.decode(encoding="utf-8", errors="replace"))
                    if packet.get("index") is not None:
                        continue

                    layers: dict = packet["layers"]
                    con_id: str = (
                        f"{layers['tcp']['tcp_tcp_stream']}:{layers['tcp']['tcp_tcp_srcport']}"
                    )
                    dstport: str = layers["tcp"]["tcp_tcp_dstport"]
                    if dstport in self.__tempesta_tls_ports and layers.get("http2") is not None:
                        self._process_http2_request(packet, con_id)
                    elif dstport in self.__tempesta_tls_ports and layers.get("http") is not None:
                        self._process_http_request(packet, self.https_requests, con_id)
                    elif dstport in self.__tempesta_https_ports and layers.get("http") is not None:
                        self._process_http_request(packet, self.http_requests, con_id)

    def save_to_files(self) -> None:
        """Save completed messages to separate json files."""
        for messages, name in zip(
            [self.http2_requests, self.https_requests, self.http_requests],
            [self.__http2_file, self.__https_file, self.__http_file],
        ):
            with open(name, "w") as file:
                json.dump(messages, file, indent=2)

    def __remove_old_files(self) -> None:
        """Remove old files if they exist"""
        for file in [
            self.__output_file,
            self.__http2_file,
            self.__https_file,
            self.__http_file,
        ]:
            try:
                os.remove(file)
            except FileNotFoundError:
                pass

    def __extract_http_and_http2_packets(self) -> None:
        """Extract decrypted http and http2 messages from .pcap files"""
        for name in self.__tcpdump_files:
            sp.run(f'tshark -r {name} -T ek -Y "http2 or http" >> {self.__output_file}', shell=True)

    @staticmethod
    def __get_segments(packet: dict, proto: str) -> list[dict]:
        """
        Some TCP segment may contain some h2 frames.
        For example - TempestaFW return 2 DATA frames in one TCP frame."""
        segments = packet["layers"][proto]
        return segments if type(segments) is list else [segments]

    @staticmethod
    def __prepare_field(field: list[str] | str) -> list[str]:
        """As for `__get_segments` method."""
        return field if type(field) is list else [field]

    def _process_http2_request(self, packet: dict, con_id: str) -> None:
        for frame in self.__get_segments(packet, "http2"):
            if not frame or frame.get("http2_http2_magic") is not None:
                continue

            frame_types = self.__prepare_field(frame["http2_http2_type"])
            stream_ids = self.__prepare_field(frame["http2_http2_streamid"])
            flags = self.__prepare_field(frame["http2_http2_flags"])

            if self.http2_requests.get(con_id) is None:
                self.http2_requests[con_id] = list()

            for type_, stream_id, frame_flags in zip(frame_types, stream_ids, flags):
                if type_ == "4":
                    # SETTINGS frame
                    settings = {}
                    for s in [
                        "http2_http2_settings_header_table_size",
                        "http2_http2_settings_enable_push",
                        "http2_http2_settings_initial_window_size",
                        "http2_http2_settings_max_frame_size",
                        "http2_http2_settings_max_concurrent_streams",
                        "http2_http2_settings_max_header_list_size",
                    ]:
                        if frame.get(s) is not None:
                            settings[s.replace("http2_http2_settings_", "")] = int(frame.get(s))
                    if settings:
                        self.http2_requests[con_id].append(SettingsFrame(**settings))

                elif type_ == "1":
                    # HEADERS frame
                    self.http2_requests[con_id].append(
                        HeadersFrame(
                            stream_id=int(stream_id),
                            headers=[
                                (h_name, h_value)
                                for h_name, h_value in zip(
                                    frame["http2_http2_header_name"],
                                    frame["http2_http2_header_value"],
                                )
                            ],
                            flags=frame_flags,
                        )
                    )

                elif type_ == "0":
                    # DATA frame
                    if frame.get("http2_http2_body_reassembled_data") is not None:
                        body = frame["http2_http2_body_reassembled_data"]
                    else:
                        body = frame["http2_http2_data_data"]
                    self.http2_requests[con_id].append(
                        DataFrame(
                            stream_id=int(stream_id),
                            body=bytes.fromhex(body.replace(":", "")),
                            flags=frame_flags,
                        )
                    )
                elif type_ == "9":
                    # CONTINUATION frame
                    for f in self.http2_requests[con_id]:
                        if type(f) is HeadersFrame and f.stream_id == int(stream_id):
                            f.headers.append(
                                (
                                    frame["http2_http2_header_name"],
                                    frame["http2_http2_header_value"],
                                )
                            )

    def _process_http_request(self, packet: dict, requests_dict: dict, con_id: str) -> None:
        for segment in self.__get_segments(packet, "http"):
            if not segment:
                continue

            if segment.get("data") is not None:
                body = bytes.fromhex(segment["data"]["data_data_data"].replace(":", "")).decode()
            else:
                body = ""

            request = HttpRequest(
                method=segment["http_http_request_method"],
                uri=segment["http_http_request_uri"],
                version=segment["http_http_request_version"],
                headers=[
                    tuple(h.rstrip("\r\n").split(": ")) for h in segment["http_http_request_line"]
                ],
                body=body,
            )

            if self.https_requests.get(con_id):
                requests_dict[con_id].append(request)
            else:
                requests_dict[con_id] = [request]
