"""
One examination, start to finish.

Order matters and is fixed: the file is hashed before anything parses it,
integrity is checked on the raw bytes before androguard interprets them, and the
verdict is decided last from what every layer recorded. Every layer records its
own failure and the rest continue; a sample that breaks one parser should not
hide what the others can still see.
"""

import hashlib
import os
import time

from . import ENGINE_VERSION, baselines as baseline_store, endpoints, integrity, intel, reference
from .behaviours import BEHAVIOURS, detect_behaviours, detect_capabilities
from .container import inspect_archive
from .report import skeleton
from .verdict import decide

MAX_APK_BYTES = 1024 * 1024 * 1024


def _versions():
    versions = {'engine': ENGINE_VERSION}
    for name, module in (('androguard', 'androguard'), ('apkInspector', 'apkInspector')):
        try:
            from importlib.metadata import version
            versions[name] = version(module)
        except Exception:
            versions[name] = 'unknown'
    return versions


def _hashes(path):
    digests = {'sha256': hashlib.sha256(), 'sha1': hashlib.sha1(), 'md5': hashlib.md5()}
    size = 0
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            size += len(block)
            for digest in digests.values():
                digest.update(block)
    return dict({k: v.hexdigest() for k, v in digests.items()}, size=size)


def examine(apk_path, container_path=None, original_name='', baselines=None):
    started = time.monotonic()
    baselines = baseline_store.load() if baselines is None else baselines
    report = skeleton()
    report['engine'] = dict(_versions(),
                            reference_data=reference.sources(),
                            baselines={'measured_at': baselines.get('measured_at', ''),
                                       'corpus': {k: v for k, v in baselines.get('corpus', {}).items()
                                                  if k != 'manifest'}})
    errors = report['errors']

    report['file'] = dict(_hashes(apk_path), name=original_name or os.path.basename(apk_path))
    if container_path:
        report['container'] = dict(inspect_archive(container_path), sha256=_hashes(container_path)['sha256'])

    if report['file']['size'] > MAX_APK_BYTES:
        errors.append('Package larger than the examination limit; not parsed.')
        report['assessment'] = decide(None, [], None, False, False)
        return report

    with open(apk_path, 'rb') as handle:
        raw = handle.read()

    # ── integrity, on the raw bytes ───────────────────────────────────────
    report['integrity'] = integrity.check(raw)
    if report['integrity']['error']:
        errors.append(report['integrity']['error'])
    for finding in report['integrity']['findings']:
        finding['baseline'] = baseline_store.status(baselines, finding['id'])

    # ── identity and code, through androguard ─────────────────────────────
    from loguru import logger
    logger.disable('androguard')
    identity = codemap = None
    try:
        from androguard.core.apk import APK
        from .identity import read_identity
        apk = APK(apk_path, raw=False)
        identity = read_identity(apk)
        errors.extend(identity.pop('errors'))
        for cert in identity['signing']['certificates']:
            for anomaly in cert['subject_anomalies']:
                anomaly['baseline'] = baseline_store.status(baselines, anomaly['id'])
            cert['debug_baseline'] = baseline_store.status(baselines, 'cert.debug_certificate')
        report['identity'] = identity
    except Exception as exc:
        errors.append(f'The package could not be parsed as an Android application: {exc}')

    examined_manifest = bool(identity and identity.get('package'))
    examined_code = False
    host_list = []
    if identity:
        try:
            from .codemap import CodeMap
            codemap = CodeMap(apk, identity, reference.tracker_code_prefixes())
            errors.extend(codemap.errors)
            # A resource-only package (no classes*.dex at all) has been fully
            # examined; a package whose DEX files failed to parse has not.
            has_dex_entries = any(name.endswith('.dex') and name.startswith('classes')
                                  for name in apk.get_files())
            examined_code = ((codemap.dex_count > 0 or not has_dex_entries)
                             and not codemap.truncated)
            report['code'] = {'dex_files': codemap.dex_count, 'dex_bytes': codemap.dex_bytes,
                              'truncated': codemap.truncated, 'no_code': not has_dex_entries,
                              'app_namespaces': list(codemap._app_prefixes)}
        except Exception as exc:
            errors.append(f'Code could not be indexed: {exc}')

    if codemap is not None and codemap.dex_count:
        ctx, capabilities = detect_capabilities(identity, codemap)
        for capability in capabilities:
            capability['baseline'] = baseline_store.status(baselines, capability['id'])
        report['capabilities'] = capabilities
        behaviours = detect_behaviours(ctx)
        for behaviour in behaviours:
            behaviour['baseline'] = baseline_store.status(baselines, behaviour['id'])
        report['behaviours'] = behaviours
        try:
            report['endpoints'] = endpoints.extract(codemap)
            host_list, _ips = endpoints.hosts_for_correlation(report['endpoints'])
        except Exception as exc:
            errors.append(f'Endpoints could not be extracted: {exc}')

    report['intel'] = intel.match(report['file']['sha256'], identity, host_list)
    report['assessment'] = decide(report['integrity'], report['behaviours'], report['intel'],
                                  examined_code, examined_manifest)
    report['engine']['seconds'] = round(time.monotonic() - started, 2)
    return report


def signals(report):
    """
    Every signal a report contains, as {signal_id: fired}.

    Independent of baselines, so evaluation measures raw behaviour and not the
    statuses it is about to produce.
    """
    fired = {}
    for finding in (report.get('integrity') or {}).get('findings', []):
        fired[finding['id']] = True
    for capability in report.get('capabilities') or []:
        fired[capability['id']] = capability['present']
    detected = {b['id'] for b in report.get('behaviours') or []}
    for rule in BEHAVIOURS:
        fired[rule['id']] = rule['id'] in detected
    certificates = ((report.get('identity') or {}).get('signing') or {}).get('certificates', [])
    fired['cert.debug_certificate'] = any(c['debug_certificate'] for c in certificates)
    fired['cert.malformed_country'] = any(
        a['id'] == 'cert.malformed_country' for c in certificates for a in c['subject_anomalies'])
    return fired
