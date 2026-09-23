"""Time zone identifiers offered to account holders.

The account UI used to build its time zone list in the browser with
`Intl.supportedValuesOf("timeZone")`, but that list varies with the browser's
ICU version, so some users were offered identifiers CoManage Registry rejects
on save. CoManage exposes no API for its own list, so we generate one here from
the IANA time zone database that ships with the OS (via `zoneinfo`), filtered to
match what CoManage accepts.
"""

import logging
from functools import cache
from pathlib import Path
from zoneinfo import TZPATH, available_timezones

# The app's logger, by name, so this module stays importable without the app
# config that services.logs_service loads.
logger = logging.getLogger("access_account_api")

# CoManage Registry is a CakePHP application and builds its time zone list from
# PHP's DateTimeZone::listIdentifiers(DateTimeZone::ALL), which holds one
# identifier per country/region plus "UTC" (419 entries as of tzdata 2026b).
# The IANA database ships that same set as `zone.tab`, so we filter against it:
# it excludes both the deprecated aliases CoManage rejects (`Asia/Calcutta`,
# `Europe/Kiev`, `America/Buenos_Aires`, `US/Eastern`, `Egypt`) and the
# fixed-offset (`Etc/GMT+5`) and placeholder (`Factory`) zones, while keeping
# the current names of places whose zone data has been merged with a neighbor's
# (`Europe/Oslo`, `Asia/Kuala_Lumpur`, `Pacific/Wallis`).
ZONE_TAB = "zone.tab"

# Identifiers that belong to no country and so are absent from zone.tab, but are
# still accepted by CoManage.
UNGROUPED_TIME_ZONES = frozenset({"UTC"})

# Fallback filter, used only if zone.tab can't be found (see get_time_zones).
# These are the region groups PHP's list is built from; filtering on them alone
# keeps the deprecated aliases that share a region prefix, so it is a
# last resort rather than the normal path.
TIME_ZONE_REGIONS = frozenset(
    {
        "Africa",
        "America",
        "Antarctica",
        "Arctic",
        "Asia",
        "Atlantic",
        "Australia",
        "Europe",
        "Indian",
        "Pacific",
    }
)


def _zone_tab_directories() -> list[Path]:
    """Directories that may hold zone.tab, in the order zoneinfo searches them.

    The system tz database (TZPATH) comes first. The `tzdata` package ships its
    own copy, which `zoneinfo` falls back to for zone data, so check it too.
    """
    directories = [Path(directory) for directory in TZPATH]
    try:
        import tzdata.zoneinfo

        directories.extend(Path(path) for path in tzdata.zoneinfo.__path__)
    except ImportError:
        pass
    return directories


def _read_zone_tab() -> set[str]:
    """Return the identifiers listed in the first zone.tab we can read.

    Rows are tab-separated: country code, coordinates, identifier, and an
    optional comment. Comment lines start with "#".
    """
    for directory in _zone_tab_directories():
        try:
            rows = (directory / ZONE_TAB).read_text().splitlines()
        except OSError:
            continue

        zones = {
            fields[2]
            for row in rows
            if not row.startswith("#") and len(fields := row.split()) > 2
        }
        if zones:
            return zones

    return set()


@cache
def get_time_zones() -> list[str]:
    """Return the sorted time zone identifiers a user may choose from.

    Cached for the life of the process: the underlying database only changes
    when the system's tzdata package is updated, which requires a restart to
    take effect anyway.
    """
    available = available_timezones()
    selectable = _read_zone_tab() & available

    if not selectable:
        # No readable zone.tab. Rather than leave the UI with no time zones at
        # all — which would clear the time zone of anyone who saves their
        # profile — fall back to the region groups, and log it, since that list
        # includes aliases CoManage rejects.
        logger.warning(
            "Could not read %s from %s; falling back to region-prefix time zone filter",
            ZONE_TAB,
            [str(directory) for directory in _zone_tab_directories()],
        )
        selectable = {
            zone for zone in available if zone.split("/", 1)[0] in TIME_ZONE_REGIONS
        }

    return sorted(selectable | (UNGROUPED_TIME_ZONES & available))
