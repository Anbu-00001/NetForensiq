"""
One place the version is written down.

The landing page carried `NETFORENSIQ v1.0` as a literal, which would have
gone on saying v1.0 through every release. The VERSION file at the repository
root is the source; the API serves it and the UI reads it from there.
"""

import os
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# Two locations, because the file sits in two different places depending on how
# the platform was deployed. In a checkout it is at the repository root, a
# level above `backend/`. In the container the image carries only `backend/`,
# so it is copied in beside the code. Looking in one place meant the container
# reported "0.0.0-unknown" on its own landing page.
_CANDIDATES = (
    _HERE.parent.parent / 'VERSION',   # repository checkout
    _HERE.parent / 'VERSION',          # container image
)


def get_version():
    # An explicit value wins, so a build can stamp one without a file at all.
    stamped = os.getenv('NETFORENSIQ_VERSION', '').strip()
    if stamped:
        return stamped

    for candidate in _CANDIDATES:
        try:
            value = candidate.read_text().strip()
        except OSError:
            continue
        if value:
            return value

    # A deployment that ships without the file should say so rather than claim
    # a version it cannot substantiate.
    return '0.0.0-unknown'
