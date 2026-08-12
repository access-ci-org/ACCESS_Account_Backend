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


def obfuscate_string(value: str, char: str = "*") -> str:
    """Mask the middle portion of a string, keeping its outer edges visible.

    The number of characters replaced is half the string's length (rounded up,
    at least 1), centered within the string.
    """
    length = len(value)
    replace = max(-(-length // 2), 1)
    start = (length - replace) // 2
    return value[:start] + char * replace + value[start + replace :]


def obfuscate_email(address: str | None) -> str | None:
    """Obfuscate the account and domain portions of an email address separately.

    Returns None if ``address`` is falsy or does not contain an "@".
    """
    if not address:
        return None
    account, sep, domain = address.partition("@")
    if not sep:
        return None
    return obfuscate_string(account) + "@" + obfuscate_string(domain)
