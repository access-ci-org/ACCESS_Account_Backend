def safe_get(d: dict, *keys, default=None):
    """Safely get a nested value from a dictionary."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
