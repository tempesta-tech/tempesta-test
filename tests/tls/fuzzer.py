import random
from struct import pack

from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TlsRecordGenerator:

    # Format: {'value name': [current_id, (list of available values)]}
    # Repeated values make are more frequently tested (see next()).
    values = {
        # TLS record header values.
        "type": [0, (0, 0x14, 0x15, 0x16, 0x17, 0xFF)],
        "major": [0, (0xFF, 3, 3, 3, 3, 3, 3)],
        "minor": [0, (2, 3, 3, 3, 3, 3, 4)],
        "delta_length": [0, (-17, -1, 0, 10, 0, 29, 1000)],
        # Handshake values.
        "hs_type": [0, (0, 1, 2, 3, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x14, 0x1F)],
        "hs_delta_length": [0, (-7, -2, 0, 11, 0, 51, 97)],
        # Payload lengths.
        "payload": [0, (0, 1, 11, 43, 64, 127, 256, 563, 2048, 9973, 17000)],
        "extra_len": [0, (0, 0, 0xF, 0, 0, 0xF0, 0, 0)],
    }

    def __curr_value(self, vname):
        vals = self.values[vname]
        return vals[1][vals[0]]

    def print_curr_state(self):
        msg = "fuzzer try:"
        for k, val in self.values.items():
            msg += " %s=%x" % (k, val[1][val[0]])
        tf_cfg.dbg(2, msg)

    def record(self):
        """
        Generates "handshake" messages only in this case there are no much
        difference between invalid handshake bytes or random payload for
        application data records. At least in this simple fuzzer.
        """
        p_real_len = self.__curr_value("payload")
        # Handshake header length is 4 bytes.
        p_len = p_real_len + self.__curr_value("delta_length") + 4
        if p_len < 0:
            p_len = 0
        hs_len = p_real_len + self.__curr_value("hs_delta_length")
        if hs_len < 0:
            hs_len = 0
        msg = pack(
            "!BBBHBBH",
            self.__curr_value("type"),
            self.__curr_value("major"),
            self.__curr_value("minor"),
            p_len,
            self.__curr_value("hs_type"),
            # Handshake length is always < 2^16, so this byte
            # is normally zero.
            self.__curr_value("extra_len"),
            hs_len,
        )
        if p_real_len:
            msg += pack(str(p_real_len) + "s", str(random.getrandbits(8 * p_real_len)))
        return msg

    def next(self):
        """
        The full power of all possible cobinations of values is quite large,
        even in the first very simple implementation, so it's not practical
        to try each possible combination of values, so we move all values
        iterators at once. It makes sense for a caller to execute several
        full cycles to get more combinations.

        TODO Pure-software random number generators take a seed, so it can be
        used here.
        """
        for _, val in self.values.items():
            val[0] = (val[0] + 1) % len(val[1])


def tls_record_fuzzer():
    gen = TlsRecordGenerator()
    while True:
        gen.print_curr_state()
        yield gen.record()
        gen.next()
