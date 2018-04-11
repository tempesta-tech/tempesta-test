from helpers import tf_cfg
from string import Template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def fill_template(template, extra_kvs = {}):
    kvs = tf_cfg.cfg.kvs.copy()
    kvs.update(extra_kvs)
    return Template(template).substitute(kvs)
