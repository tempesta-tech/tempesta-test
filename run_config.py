from helpers import tf_cfg

SAVE_SECRETS = False

# General params from tests_config.ini
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))

THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))

DURATION = int(tf_cfg.cfg.get("General", "duration"))
