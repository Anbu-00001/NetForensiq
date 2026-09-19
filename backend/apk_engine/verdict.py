"""
From findings to a tier — the strongest level of evidence reached, never a sum.

Rules of the decision, all visible in the report:

* Tier 4 needs an identity match (file hash or signing certificate) in a
  bundled indicator set.
* Tier 3 needs a behaviour whose rule is tier 3 and whose status is
  *validated* (baselines.py).
* Tier 2 needs a validated integrity indicator, or a validated tier-2 behaviour.
* Tier 3 or 2 can also be reached by an identity finding — the package is not
  signed by the key the reference set records for the name it claims
  (reference_set.py). Like an intelligence identity match, and unlike every
  behavioural signal, this is ungated by a baseline: it compares two
  certificate digests rather than firing on a pattern, so a benign base rate
  is not the thing that could make it wrong. What could is a wrong reference
  entry, so the entry's own source travels with the finding.
* Otherwise tier 1 if the manifest and code were both examined, tier 0 if not.

Experimental and unmeasured findings are still reported — under
``not_established``, with their counts — so the examiner sees them without the
system claiming more than it has measured.

Families are never assigned directly. A PHA category appears only because a
validated behaviour that carries one appears, and it lists that behaviour as its
basis; an intelligence match names the product and category the source gave.
"""

from .report import IDENTITY_TIERS, assessment_for
from .sources import PHA, SOURCES


def decide(integrity, behaviours, intel, examined_code, examined_manifest, reference=None,
           gaps=()):
    basis, not_established, families, techniques = [], [], {}, {}

    def note(item, kind):
        return {'kind': kind, 'id': item['id'], 'title': item['title'],
                'status': item['baseline']['status'],
                'benign_fired': item['baseline']['benign_fired'],
                'benign_n': item['baseline']['benign_n']}

    def add_techniques(item):
        for technique in item.get('attack', []):
            techniques.setdefault(technique['id'], dict(technique, established_by=[]))
            techniques[technique['id']]['established_by'].append(item['id'])

    # Two running maxima rather than one, because the *words* depend on what
    # reached the tier: an identity finding alone must not be described as a
    # demonstrated behaviour.
    tier = behavioural_tier = 1 if (examined_code and examined_manifest) else 0
    identity_tier = 0

    if intel and intel.get('identity_match'):
        behavioural_tier = 4
        for match in intel['matches']:
            if match['strength'] == 'identity':
                basis.append({'kind': 'intel', 'id': f"intel.{match['kind']}",
                              'title': f"{match['kind'].replace('_', ' ')} matches {match['product']}",
                              'source': match['source'], 'snapshot': match['snapshot']})
                families.setdefault('stalkerware', {
                    'category': PHA['stalkerware']['name'],
                    'definition': PHA['stalkerware']['definition'],
                    'definition_source': SOURCES['google-pha']['url'],
                    'product': match['product'], 'established_by': []})
                families['stalkerware']['established_by'].append(f"intel.{match['kind']}")

    for finding in (reference or {}).get('findings', []):
        if finding.get('establishes') != 'identity':
            continue        # a claim worth reading, not a fact that sets the tier
        identity_tier = max(identity_tier, finding['tier'])
        basis.append({'kind': 'identity', 'id': finding['id'], 'title': finding['title'],
                      'statement': finding['statement'], 'tier': finding['tier'],
                      'source': finding.get('source', {})})

    for finding in behaviours:
        if finding['baseline']['status'] != 'validated':
            not_established.append(note(finding, 'behaviour'))
            continue
        behavioural_tier = max(behavioural_tier, finding['tier'])
        basis.append(note(finding, 'behaviour'))
        add_techniques(finding)
        if finding.get('pha'):
            pha = PHA[finding['pha']]
            family = families.setdefault(finding['pha'], {
                'category': pha['name'], 'definition': pha['definition'],
                'definition_source': SOURCES['google-pha']['url'], 'established_by': []})
            family['established_by'].append(finding['id'])

    for finding in (integrity or {}).get('findings', []):
        if finding['baseline']['status'] != 'validated':
            not_established.append(note(finding, 'integrity'))
            continue
        behavioural_tier = max(behavioural_tier, 2)
        basis.append(note(finding, 'integrity'))
        add_techniques(finding)

    # Words follow whatever actually reached the tier. If only an identity
    # finding did, saying "harmful behaviour demonstrated" would assert
    # something no rule established.
    tier = max(behavioural_tier, identity_tier)
    identity_only = identity_tier == tier and behavioural_tier < tier
    return assessment_for(
        tier, basis=basis, families=list(families.values()),
        techniques=list(techniques.values()), not_established=not_established,
        summary=_summary(tier, basis, behaviours, intel),
        vocabulary=IDENTITY_TIERS if identity_only and tier in IDENTITY_TIERS else None,
        gaps=gaps)


def _summary(tier, basis, behaviours, intel):
    """
    One sentence an officer can read out, naming what was actually found.

    The generic tier wording stays in ``meaning``; this says which behaviour,
    in whose code, and how it compares with the legitimate corpus — the three
    things a magistrate would ask next.
    """
    if tier == 4 and intel:
        identity = [m for m in intel['matches'] if m['strength'] == 'identity']
        products = sorted({m['product'] for m in identity})
        kinds = sorted({m['kind'].replace('_', ' ') for m in identity})
        source = (intel.get('checked_against') or {}).get('source') or identity[0]['source']
        return (f"The {' and '.join(kinds)} of this package is listed by "
                f"{source} as {', '.join(products)}.")

    # An identity fact is the plainest sentence available, so it leads whenever
    # it is what set the tier.
    identity_basis = [b for b in basis if b['kind'] == 'identity' and b['tier'] == tier]
    if identity_basis:
        return identity_basis[0]['statement']

    established = [b for b in behaviours if b['baseline']['status'] == 'validated']
    if tier == 3 and established:
        titles = '; '.join(b['title'][0].lower() + b['title'][1:] for b in established)
        corpus = established[0]['baseline']
        return (f"This package's own code {titles}. "
                f"{'That combination' if len(established) == 1 else 'Those combinations'} "
                f"did not occur in any of the {corpus['benign_n']} legitimate apps measured.")

    integrity_basis = [b for b in basis if b['kind'] == 'integrity']
    if tier == 2 and integrity_basis:
        return ('The package is built in ways that defeat analysis tools while remaining '
                f"installable: {'; '.join(b['title'].lower() for b in integrity_basis)}. "
                f"None of the {integrity_basis[0]['benign_n']} legitimate apps measured is "
                'built this way.')
    return None
