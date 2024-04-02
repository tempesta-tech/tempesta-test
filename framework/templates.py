from string import Template

from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"


def populate_properties(user_properties):
    gen_properties = tf_cfg.cfg.kvs.copy()
    user_properties.update(gen_properties)


def fill_template(template, properties):
    properties["http_content_encoding"] = "$http_content_encoding"
    return Template(template).substitute(properties)
