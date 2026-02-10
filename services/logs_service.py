import logging

# Config logging
logger = logging.getLogger("access_account_api")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)
