# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Who made this, where it lives, and under what terms — stated once.

Why this module exists
======================
Authorship appears in LICENSE, NOTICE.md, CITATION.cff, the header of every
source file, the Docker image labels and the running application. Written out
separately in each place, they drift: one gets updated and the others quietly
keep an old name. `capture/tests_provenance.py` holds every one of those copies
to the values below, so changing the author or the repository URL is a change
made here and nowhere else.

What attribution does and does not do
=====================================
NetForensiq is MIT-licensed and meant to be used, forked and built on. The MIT
licence's one condition is that "the above copyright notice and this permission
notice shall be included in all copies or substantial portions of the
Software" — so a copy that keeps the notice credits the author, and a copy
presented as someone else's original work has to remove it first. Removing it
breaks the licence; it does not change who wrote the code. PROVENANCE/ holds a
timestamped proof of what existed when, which is how that question is settled.
"""

AUTHOR = 'Anbuchelvan Ganesan'
PROJECT = 'NetForensiq'
YEAR = 2026
REPOSITORY = 'https://github.com/Anbu-00001/NetForensiq'
LICENSE = 'MIT'
ORIGIN = ('Built for KANAD S.H.I.E.L.D. 2026, the Ahmedabad City Police cybercrime '
          'hackathon run by the Cyber Crime Branch with i-Hub Gujarat.')

COPYRIGHT = f'Copyright (c) {YEAR} {AUTHOR}'
SPDX_LINES = (
    f'SPDX-License-Identifier: {LICENSE}',
    f'{COPYRIGHT} — {PROJECT} ({REPOSITORY})',
)


def as_dict():
    """The same facts, for the API and anything else that serialises them."""
    return {
        'project': PROJECT,
        'author': AUTHOR,
        'copyright': COPYRIGHT,
        'license': LICENSE,
        'repository': REPOSITORY,
        'origin': ORIGIN,
    }
