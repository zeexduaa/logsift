from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsift.timeparse import Clock

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 19, 8, 0, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def clock():
    """UTC and a fixed "now", so tests don't depend on the machine's time zone or the date."""
    return Clock(timezone.utc, now=NOW)
