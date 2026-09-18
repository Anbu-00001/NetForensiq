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
        'code': None,
        'errors': [],
        'limits': LIMITS,
    }


def assessment_for(tier, basis=(), families=(), techniques=(), not_established=(), summary=None):
    label, meaning = TIERS[tier]
    return {
        'tier': tier, 'label': label, 'meaning': meaning,
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
