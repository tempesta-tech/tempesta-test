import h2.frame_buffer

from helpers import tf_cfg

# This is necessary for tests when response headers exceed 64 CONTINUATION frames.
h2.frame_buffer.CONTINUATION_BACKLOG = 100000

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
# Server params from tests_config.ini
# ------------------------------------

# user login for tempesta-tech tests with LXCServer
WEBSITE_USER = tf_cfg.cfg.get("Server", "website_user")

# user password for tempesta-tech tests with LXCServer
WEBSITE_PASSWORD = tf_cfg.cfg.get("Server", "website_password")

# ------------------------------------
# Global params from run_tests.py
# ------------------------------------

# save tls secrets for curl and deproxy clients
SAVE_SECRETS = False

# size (bytes) of TCP segment. This uses only for deproxy client and server.
TCP_SEGMENTATION = 0

# Enable or disable deproxy auto parser. Enable if True
AUTO_PARSER = True
