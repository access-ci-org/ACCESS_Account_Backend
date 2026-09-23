"""Unit tests for services.time_zone_service.get_time_zones (pure function)."""

from zoneinfo import ZoneInfo

import pytest

from services import time_zone_service
from services.time_zone_service import TIME_ZONE_REGIONS, get_time_zones


@pytest.fixture(autouse=True)
def clear_cache():
    # get_time_zones() is cached for the life of the process.
    get_time_zones.cache_clear()
    yield
    get_time_zones.cache_clear()


def test_returns_sorted_unique_identifiers():
    zones = get_time_zones()
    assert zones == sorted(zones)
    assert len(zones) == len(set(zones))
    # zone.tab holds roughly 420 identifiers; a much shorter list means the
    # system tz database is missing or the filter is wrong.
    assert len(zones) > 300


def test_every_identifier_is_loadable():
    # Guards against offering the UI a name CoManage (or Python) can't resolve.
    for zone in get_time_zones():
        ZoneInfo(zone)


def test_includes_current_identifiers_and_utc():
    zones = set(get_time_zones())
    assert {"America/New_York", "Europe/London", "Pacific/Auckland", "UTC"} <= zones
    # Places whose zone data has been merged into a neighbor's keep their own
    # identifier in zone.tab, and CoManage accepts them.
    assert {"Europe/Oslo", "Europe/Amsterdam", "Asia/Kuala_Lumpur"} <= zones


def test_excludes_identifiers_comanage_rejects():
    zones = set(get_time_zones())
    # Deprecated aliases. CoManage is known to reject Asia/Calcutta; the rest
    # are excluded from PHP's list the same way.
    assert not zones & {
        "Asia/Calcutta",
        "Europe/Kiev",
        "America/Buenos_Aires",
        "Asia/Rangoon",
        "Atlantic/Faeroe",
    }
    # Country groupings, legacy single-name zones, fixed offsets, and the
    # "Factory" placeholder are absent from CoManage's list too.
    assert not zones & {"US/Eastern", "Canada/Central", "Egypt", "Zulu", "Factory"}
    assert not any(zone.startswith("Etc/") for zone in zones)


def test_falls_back_to_region_filter_without_zone_tab(monkeypatch, caplog):
    # A deployment whose tz database has no zone.tab still gets a usable list
    # (with a warning), rather than an empty select that would wipe the time
    # zone of anyone who saves their profile.
    monkeypatch.setattr(time_zone_service, "_read_zone_tab", set)

    with caplog.at_level("WARNING"):
        zones = get_time_zones()

    assert "zone.tab" in caplog.text
    assert "UTC" in zones
    assert "America/New_York" in zones
    for zone in zones:
        assert zone == "UTC" or zone.split("/", 1)[0] in TIME_ZONE_REGIONS


def test_reads_zone_tab_rows(tmp_path, monkeypatch):
    zone_tab = tmp_path / "zone.tab"
    zone_tab.write_text(
        "# comment line\n"
        "US\t+404251-0740023\tAmerica/New_York\n"
        "GB\t+513030-0000731\tEurope/London\tcomment with spaces\n"
        "XX\t+0000+00000\tNot/ARealZone\n"
        "\n"
    )
    monkeypatch.setattr(time_zone_service, "_zone_tab_directories", lambda: [tmp_path])

    # Identifiers the tz database doesn't actually have are dropped, and UTC is
    # added even though zone.tab never lists it.
    assert get_time_zones() == ["America/New_York", "Europe/London", "UTC"]
