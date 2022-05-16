"""Filter auto generator module."""
import os
import sys
from typing import Union
from ipaddress import ip_address, IPv6Address

from jinja2 import Environment, FileSystemLoader


NEW_GENERATED_FILE_NAME = 'config_for_tests.py'
TEMPLATE_FILE = 'config_for_tests_template.txt'

IPv4 = '127.0.0.{0}'
IPv4_H2 = '127.0.1.{0}'
IPv4_HTTPS = '127.0.2.{0}'
IPv6 = '::1'


class ConfigAutoGenerator(object):
    """Config auto generator."""

    current_dir = os.path.dirname(os.path.abspath(__file__))
    filter_template = TEMPLATE_FILE

    def __init__(self):
        """
        Init class instance.

        """
        self.filter_source = []
        self.all_clients = []
        self.listen = []
        self.counter = 0
        self.port_number = 8080

    def generate(self):
        """
        Generate config

        Raises:
            NotImplementedError: if error

        """
        new_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            NEW_GENERATED_FILE_NAME,
        )
        try:
            new_config = self.make_config_file()
        except Exception:
            sys.stdout.write(
                '[ERROR] Config generating was failed.\n',
            )
            raise NotImplementedError
        with open(new_file, 'w') as nf:
            nf.write(new_config)

    def make_config_file(self) -> str:
        """
        Make config file.

        Returns:
            config (str): new config

        """
        j2_env = Environment(  # noqa:S701
            loader=FileSystemLoader(self.current_dir),
            trim_blocks=True,
        )
        self.make_config()

        return j2_env.get_template(
            self.filter_template,
        ).render(
            clients=self.all_clients,
            listen=set(self.listen),
        )

    def make_config(self, quantity_ip=5, quantity_port=5):

        for ip_tail in range(4, quantity_ip + 4):
            for port_tail in range(1, quantity_port + 1):
                ipv4 = IPv6.format(str(ip_tail))
                ipv4_h2 = IPv4_H2.format(str(ip_tail))
                ipv4_https = IPv4_HTTPS.format(str(ip_tail))

                # listen 127.0.0.1: 8080 proto = h2;
                self._add_client(
                    ip_addr=ipv4_h2,
                    port=self.port_number,
                    proto='h2',
                )

                # listen 127.0.0.1 proto = h2;
                self._add_client(ip_addr=ipv4_h2, proto='h2')

                # listen 127.0.0.1:8080;
                self._add_client(ip_addr=ipv4, port=self.port_number)

                # listen 127.0.0.1:8080 proto = https;
                self._add_client(
                    ip_addr=ipv4_https,
                    port=self.port_number,
                    proto='https',
                )

                # listen 443 proto = h2;
                self._add_client(port='443', proto='h2')

                # listen [::1]:8080;
                self._add_client(ip_addr=IPv6, port=self.port_number)

                # TODO listen [::1]:8080 proto=https;
                #self._add_client(
                #    ip_addr=IPv6,
                #    port=self.port_number-1000,
                #    proto='https',
                #)

                # listen [::1]:8080 proto=h2;
                self._add_client(
                    ip_addr=IPv6,
                    port=self.port_number - 1500,
                    proto='h2',
                )

                self.port_number += 1

    def _add_client(
        self,
        ip_addr: str = '0.0.0.0',
        port: Union[str, int] = '80',
        proto: str = '',
    ):
        if ip_addr and type(ip_address(ip_addr)) is IPv6Address:
            ip_addr = '[{0}]'.format(ip_addr)
        self.counter += 1
        self.all_clients.append(
            {
                'id': '{0}-{1}'.format(
                    'h2spec' if proto == 'h2' else 'curl',
                    self.counter,
                ),
                'addr': ip_addr,
                'port': port,
                'proto': proto if proto else '',
            }
        )
        self._append_listen(
            ip_addr=ip_addr,
            port=port,
            proto=proto,
        )

    def _append_listen(self, ip_addr: str, port: str, proto: str = ''):
        self.listen.append(
            'listen {ip}{port}{proto};'.format(
                ip=ip_addr if ip_addr != '0.0.0.0' else '',
                port='{1}{0}'.format(
                    port if port != '80' else '',
                    ':' if port != '80' and ip_addr != '0.0.0.0' else '',
                ),
                proto=' proto={0}'.format(proto) if proto else '',
            ),
        )
