import h2.frame_buffer

from helpers import tf_cfg

# This is necessary for tests when response headers exceed 64 CONTINUATION frames.
h2.frame_buffer.CONTINUATION_BACKLOG = 100000

SAVE_SECRETS = False

NO_RELOAD = False

# General params from tests_config.ini
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))

THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))

DURATION = int(tf_cfg.cfg.get("General", "duration"))

TCP_SEGMENTATION = 0
