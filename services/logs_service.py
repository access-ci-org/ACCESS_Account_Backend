import logging

from config import DEBUG, LOG_FILE_PATH

# Config logging
logger = logging.getLogger("access_account_api")
logger.setLevel(logging.INFO)

# In debug mode, log to stderr so messages show up in the console. Otherwise,
# write directly to a file -- gunicorn does not capture worker stdout/stderr
# into its log files unless explicitly configured to.
handler = logging.StreamHandler() if DEBUG else logging.FileHandler(LOG_FILE_PATH)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)
