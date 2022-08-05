"""Filter auto generator module."""
import os
import sys
from config_generator.conf_tempesta import TempestaConf, ListenSocket
from typing import List, Optional

from jinja2 import Environment, FileSystemLoader


TEMPLATE_FILE = 'conf_template.txt'

# it should be global settings, current value as example
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ConfigAutoGenerator(object):
    """Config auto generator."""

    current_dir = BASE_DIR
    template = TEMPLATE_FILE

    def __init__(self, config: dict):
        """
        Init class instance.

        """
        self.config = TempestaConf(**config)
        self.filter_source = []
        self.all_clients = []
        self.listen = []
        self.counter = 0
        self.port_number = 8080

    def generate(self, output_file: Optional[str] = None):
        """
        Generate config

        Raises:
            NotImplementedError: if error

        """
        if output_file:
            new_file = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                output_file,
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
        return self.config

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

        return j2_env.get_template(
            self.template,
        ).render(
            listen_sockets=self.config.listen_sockets,
            server_groups=self.config.server_groups,
            vhosts=self.config.vhosts,
            tls_sert=self.config.tls_cert,
            tls_key=self.config.tls_key,
            cache=self.config.cache,
            http_chain=self.config.http_chain,
        )

    def update_sockets(
        self,
        sockets: List[dict],
        append: bool = False,
        output_file: Optional[str] = None,
    ):
        if not append:
            self.config.listen_sockets = []

        for sock in sockets:
            sock = ListenSocket(**sock)
            self.config.listen_sockets.append(
                sock,
            )
        return self.generate(
            output_file=output_file,
        )


# base config we can set up onw time
base_config_example = {
    'listen_sockets': [
        {
            'address': '127.0.0.1',
            'port': '8765',
            'proto': 'https',
        },
        {
            'address': '127.0.2.1',
            'port': '8764',
            'proto': 'h2',
        },
    ],
    'server_groups': [
        {
            'name': 'default',
            'address': '127.0.0.1',
            'port': '80',
        },
    ],
    'vhosts': [
        {
            'name': 'tempesta-cat',
            'proxy_pass': 'default',
        },
    ],
    'tls_cert': 'root.crt',
    'tls_key': 'root.key',
    'http_chain': [
        '-> tempesta-cat',
    ],
}


# create config gen instance (validations here)
conf_gen = ConfigAutoGenerator(
    config=base_config_example,
)


# return config and generate config file if needed
print(
    conf_gen.generate(output_file='autogen_1.txt'),
)


# for example if we want to change only sockets,
# we should pass only new sockets data
new_listen_sockets = [
    {
        'address': '198.3.3.3',
        'port': '8765',
        'proto': 'https',
    },
    {
        'address': '202.0.2.1',
        'port': '8764',
        'proto': 'h2',
    },
]


# update and generate new config
print(
    conf_gen.update_sockets(
        sockets=new_listen_sockets,
        output_file='autogen_2.txt',
        append=True,
    ),
)

# Let's check new generated files in current directory
