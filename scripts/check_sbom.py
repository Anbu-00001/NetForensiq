#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Validate CycloneDX documents against CycloneDX's own JSON schema.

    python check_sbom.py sbom-os.cdx.json [more.json ...]

Uses `cyclonedx-python-lib` (installed with `cyclonedx-bom`), so it must be run with
the Python of the environment where that is installed. make_release.py does this for
every bill of materials it writes. Exit status 0 only if every file is valid.
"""
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def main(paths):
    bad = 0
    for path in paths:
        with open(path, encoding='utf-8') as handle:
            error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(handle.read())
        print(f'{path}: {"valid CycloneDX 1.6" if error is None else "INVALID: " + str(error)[:300]}')
        bad += error is not None
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
