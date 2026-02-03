import sys
from typing import Optional, Union

from framework.services import client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ExternalTester(client.Client):
    """The class allows to run various 3d-party test suites or any programs
    against Tempesta. Required properties of `client` definitions inside
    `tester.TempestaTest` class:
    - `type` - common attribute for all definitions. Must have value `external`
    - `binary` - binary to run. The `binary` value is checked against tests
        config file and alias from `Client` section can be used for that
        `binary` value. Thus full path mustn't apper in test description just
        in config file.
    - `cmd_args` - initial list of command line arguments. Can be updated
        in runtime via modifying `options` (list of strings) member.
    """

    def __init__(self, id_: str, cmd_args: str, **kwargs):
        client.Client.__init__(self, id_=id_, **kwargs)
        self.options = [cmd_args]

    def clear_stats(self) -> None:
        super().clear_stats()
        self.response_msg: Optional[str] = None
        self.__stdout = b""
        self.__stderr = b""

    @property
    def stdout(self) -> bytes:
        return self.__stdout

    @property
    def stderr(self) -> bytes:
        return self.__stderr

    def form_command(self):
        if "python3" == self.bin:
            # We must set the path to python3 from the virtual environment
            # to avoid using other versions of python3
            self.bin = sys.executable
        cmd = " ".join([self.bin] + self.options)
        return cmd

    def parse_out(self, stdout: Union[str, bytes], stderr: Union[str, bytes]):
        self.__stdout = stdout
        self.__stderr = stderr
        try:
            self.response_msg = stdout.decode() if stdout else stderr.decode()
        # if `stdout` or `std_err` is `str` already,i.e. AttributeError: 'str' object has no attribute 'decode'
        except AttributeError:
            self.response_msg = stdout if stdout else stderr
        return True
