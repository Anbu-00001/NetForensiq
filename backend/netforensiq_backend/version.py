"""
One place the version is written down.

The landing page carried `NETFORENSIQ v1.0` as a literal, which would have
gone on saying v1.0 through every release. The VERSION file at the repository
root is the source; the API serves it and the UI reads it from there.
"""

from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parent.parent.parent / 'VERSION'


def get_version():
    try:
        return _VERSION_FILE.read_text().strip() or '0.0.0-dev'
    except OSError:
        # A deployment that ships without the file should say so rather than
        # claim a version it cannot substantiate.
        return '0.0.0-unknown'
