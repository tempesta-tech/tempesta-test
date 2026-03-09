import h2.frame_buffer

from framework.helpers import tf_cfg

# This is necessary for tests when response headers exceed 64 CONTINUATION frames.
h2.frame_buffer.CONTINUATION_BACKLOG = 100000

asyncio_freq = float(tf_cfg.cfg.get("General", "asyncio_freq"))
# ------------------------------------
# General params from tests_config.ini
# ------------------------------------

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))

# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))

# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))

# ------------------------------------
# Global params from run_tests.py
# ------------------------------------

# save tls secrets for curl and deproxy clients
SAVE_SECRETS = False

# size (bytes) of TCP segment. This uses only for deproxy client and server.
TCP_SEGMENTATION = 0

# Enable or disable deproxy auto parser. Enable if True
AUTO_PARSER = True

# Enable or disable checks for memory leaks for all tests
CHECK_MEMORY_LEAKS = False
MEMORY_LEAK_THRESHOLD = int(tf_cfg.cfg.get("General", "memory_leak_threshold"))  # KB

# run tests for debug kernel (kernel with kmemleak etc.)
KERNEL_DBG_TESTS = False
