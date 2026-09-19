"""
The report's fixed vocabulary, importable without androguard.

The web process uses ``unexaminable`` when the engine process itself fails —
times out, runs out of memory, or writes something that is not a report — so
that failure is still reported in the same shape, as tier 0, and never as an
absence of findings.
"""

from . import ENGINE_VERSION, REPORT_SCHEMA

# The words are chosen to be weaker than they could be. Tier 1 in particular
# never says "safe": static examination cannot see code fetched at runtime, and
# a behaviour this engine has no rule for is still a behaviour.
TIERS = {
    4: ('Known harmful software',
        'The file, or the key that signed it, is attributed to a named harmful product by a '
        'published indicator set.'),
    3: ('Harmful behaviour demonstrated',
        "The package's own code contains a combination of behaviours that published threat "
        'research documents in malware, and that did not occur in any app of the legitimate '
        'reference corpus.'),
    2: ('Built to evade inspection',
        'The package is constructed to defeat analysis tools or to conceal itself from the '
        'user, by means that did not occur in any app of the legitimate reference corpus.'),
    1: ('No harmful behaviour established',
        'Static examination completed. The capabilities below are listed for the examiner; '
        'none of the evidence this engine treats as harmful was found. This is not a finding '
        'that the app is safe.'),
    0: ('Could not be examined',
        'The examination did not complete, so no conclusion is offered — in particular, not '
        'that nothing was found.'),
}

# A tier reached by an identity finding needs its own words. "Harmful
# behaviour demonstrated" would be false: what was demonstrated is that the
# file is not signed by the key recorded for the name it claims, which is a
# different and narrower thing.
IDENTITY_TIERS = {
    3: ('Not the application it claims to be',
        'The package declares the name of a known application but is not signed by the key '
        'recorded as that application\'s. Android treats the signing key, not the name, as '
        'identity, so the two are not the same application.'),
    2: ('Not the recorded build of the application it claims to be',
        'The package declares the name of a known application and is signed by a different key '
        'than the build on record. That is consistent with redistribution through another '
        'channel as well as with impersonation; the reference entry says which was recorded.'),
}

LIMITS = [
    'Static examination only: the sample is never executed, so code downloaded, decrypted or '
    'generated at runtime is not seen.',
    'Behaviour rules cover documented techniques. A harmful behaviour with no rule is not '
    'detected, and tier 1 must be read as "not established", never as "safe".',
    'Code attribution is by namespace. Obfuscated code cannot be told apart from library code '
    'and is treated as the app\'s own.',
    'Call paths are found through static call edges; Android lifecycle callbacks, listeners and '
    'lambdas are not edges, so a missing path does not mean unreachable code.',
    'A signal is "validated" when it fired on none of the legitimate reference apps. The '
    'printed upper bound is how large its false-positive rate could still plausibly be.',
    'Identity findings are only as complete as the reference set they are checked against. An '
    'empty reference set means no claim was checked, never that the claim was verified.',
    'Only DEX bytecode is indexed. An app whose logic is compiled for another runtime — Flutter, '
    'React Native, .NET, Unity, Cordova — is reported with that gap named, because "nothing '
    'established" about code that was never read is not a finding about the app.',
]


def skeleton():
    return {
        'schema': REPORT_SCHEMA,
        'engine': {'version': ENGINE_VERSION},
        'file': {},
        'container': None,
        'assessment': None,
        'integrity': None,
        'identity': None,
        'capabilities': [],
        'behaviours': [],
        'endpoints': None,
        'intel': None,
        'reference_set': None,
        'reproduction': None,
        'code': None,
        'errors': [],
        'limits': LIMITS,
    }


def assessment_for(tier, basis=(), families=(), techniques=(), not_established=(), summary=None,
                   vocabulary=None, gaps=()):
    label, meaning = (vocabulary or TIERS)[tier]
    gaps = list(gaps)
    # A gap changes what tier 1 is entitled to say, so it travels with the tier
    # rather than sitting in a field a reader might miss.
    if gaps and tier == 1:
        meaning = (meaning + ' Part of this package was not examined at all — see the gaps below, '
                   'which narrow what "not established" covers.')
    return {
        'tier': tier, 'label': label, 'meaning': meaning, 'gaps': gaps,
        'summary': summary or meaning,
        'basis': list(basis), 'families': list(families), 'attack': list(techniques),
        'not_established': list(not_established),
    }


def unexaminable(reason, file_info=None, container=None):
    report = skeleton()
    report['file'] = file_info or {}
    report['container'] = container
    report['errors'].append(reason)
    report['assessment'] = assessment_for(0, summary=reason)
    return report
