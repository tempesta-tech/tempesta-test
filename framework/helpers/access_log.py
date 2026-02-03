import dataclasses
import re
import typing
from ipaddress import IPv4Address, IPv6Address

if typing.TYPE_CHECKING:
    from framework.helpers.dmesg import DmesgFinder

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclasses.dataclass
class AccessLogLine:
    address: typing.Union[IPv4Address, IPv6Address] | str
    vhost: str
    method: typing.Union[str, int]
    uri: str
    version: str
    status: int
    response_content_length: int
    referer: str
    user_agent: str
    tft: str
    tfh: str
    timestamp: typing.Optional[int] = None
    dropped_events: typing.Optional[int] = None
    response_time: typing.Optional[int] = None

    re_pattern: re.Pattern = re.compile(
        r"\[tempesta fw\] "
        r"(?P<address>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) "
        r"\"(?P<vhost>[\w.-]+)\" "
        r"\"(?P<method>[\w]+) "
        r"(?P<uri>.*) "
        r"HTTP\/(?P<version>[\d.]+)\" "
        r"(?P<status>\d+) "
        r"(?P<response_content_length>\d+) "
        r"\"(?P<referer>.*)\" "
        r"\"(?P<user_agent>.*)\" "
        r"\"tft=(?P<tft>\w+)\" "
        r"\"tfh=(?P<tfh>\w+)\"",
        flags=re.DOTALL | re.MULTILINE,
    )

    def __post_init__(self):
        self.status = int(self.status)
        self.response_content_length = int(self.response_content_length)

    def __repr__(self):
        return ", ".join(
            [
                f'{field.name} => "{getattr(self, field.name)}"'
                for field in dataclasses.fields(self)
                if not field.name.startswith("re_")
            ]
        )

    def __eq__(self, other: "AccessLogLine"):
        for name, received_result in self.__dict__.items():
            expected_result = other.__getattribute__(name)
            if name == "uri" and len(received_result) > 3 and received_result[-3:] == "...":
                expected_result = expected_result[: (len(received_result) - 3)] + "..."
            assert (
                received_result == expected_result
            ), f"Wrong '{name}' in dmesg line. Expected: {expected_result}, Received: {received_result}"
        return True

    @classmethod
    def parse_all(cls, text: str) -> typing.List["AccessLogLine"]:
        """
        Parse the text and find all the entries for access logs
        """
        lines = re.findall(cls.re_pattern, text)
        return [cls(*line) for line in lines]

    @classmethod
    def parse(cls, text: str) -> typing.Optional["AccessLogLine"]:
        """
        Parse the text and return the only one entry of the access log if exists
        """
        res = re.findall(cls.re_pattern, text)

        if not res:
            return None

        return cls(*res[0])

    @classmethod
    def from_dmesg(cls, klog: "DmesgFinder") -> typing.Optional["AccessLogLine"]:
        """
        Find the first entry of access log in dmesg
        """
        klog.update()
        logs = cls.parse_all(klog.log.decode())

        if not logs:
            return None

        return logs[0]
