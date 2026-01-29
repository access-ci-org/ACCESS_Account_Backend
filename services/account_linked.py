def prefer_comanage(comanage_val, identity_val):
    """
        Use CoManage if values present, otherwise fall back to Identity Service.
    """
    if comanage_val is None:
        return identity_val
    if isinstance(comanage_val, str) and comanage_val.strip() == "":
        return identity_val
    if isinstance(comanage_val, list) and len(comanage_val) == 0:
        return identity_val
    return comanage_val

def safe_get(d: dict, *keys, default=None):
    """Safely get a nested value from a dictionary."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur