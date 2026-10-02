# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
What this tool cannot establish, in numbers where numbers exist.

One source for three readers: the "Limits" page, the sentence an officer should
use when the tool finds nothing, and the investigation report's own limits section.
They used to say different things, and the report said stale ones ("thirty-five
thresholds", "ten rules") because it was typed, not derived.

Nothing here is typed in that can be measured:

* detection and false-positive figures come from data/validation_summary.json,
  which scripts/build_validation_report.py writes from the same results.json as the
  validation report, and a test requires it to equal a regeneration;
* the network figures come from data/rule_base_rates.json (research/157, 158);
* threshold, rule and unmapped-rule counts are read from the code.

Where the page quotes a standard, the words are the standard's. NIST SP 800-86 was
read in full (the Final version of August 2006, nvlpubs.nist.gov). ISO/IEC 27037's
text is paywalled and its own page refused a fetch; its scope is stated from
published summaries and marked as secondary, which is the convention the APK engine
already uses for sources (apk_engine/sources.py: verified / secondary).
"""
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data'


def summary():
    """The measured figures, or None if the file is absent (then nothing is claimed)."""
    try:
        return json.loads((DATA / 'validation_summary.json').read_text())
    except (OSError, ValueError):
        return None


def _pct(value, places=0):
    return f'{value * 100:.{places}f}%'


def counts():
    """Threshold, heuristic-threshold, rule and unmapped-rule counts, from the code."""
    from .attack_mapping import UNMAPPED
    from .detection import RULE_IDS, THRESHOLDS

    return {
        'thresholds': len(THRESHOLDS),
        'heuristic_thresholds': sum(1 for _, source in THRESHOLDS.values() if 'OUR HEURISTIC' in source),
        'rules': len(RULE_IDS),
        'rules_without_attack_identifier': len(UNMAPPED),
    }


def network_figures():
    """What the rate table says, for the sentences about network findings."""
    from . import base_rates

    rules = base_rates.table().get('rules', {})
    fired = sorted(r for r, v in rules.items() if v['benign_fired'] > 0 and r != 'ANOMALY_STATISTICAL')
    untested = sorted(r for r, v in rules.items()
                      if v['benign_fired'] == 0 and v['malicious_fired'] == 0)
    sample = next(iter(rules.values()), None)
    return {
        'measured': base_rates.table().get('measured'),
        'ordinary_captures': sample['benign_captures'] if sample else 0,
        'attack_captures': sample['malicious_captures'] if sample else 0,
        'rules_firing_on_ordinary_traffic': fired,
        'rules_untested': untested,
        'rules_never_seen_on_an_attack': sorted(
            r for r, v in rules.items() if v['benign_fired'] > 0 and v['malicious_fired'] == 0
            and r != 'ANOMALY_STATISTICAL'),
    }


def apk_measured(v=None):
    """How often this engine misses malware, as a sentence. None when it was not measured."""
    v = v if v is not None else summary()
    if not v:
        return None
    u = v['apk']['unseen']
    lo, hi = u['ci95']
    return (f"On {u['n']} malware samples this engine had not been built from, it reached a "
            f"tier on {u['detected']} ({_pct(u['detected'] / u['n'])}; 95% interval "
            f"{_pct(lo)}–{_pct(hi)}), reached none on {u['missed']} ({_pct(u['missed'] / u['n'])}), "
            f"and could not examine {u['could_not_be_examined']}. A sample like the one in front of "
            f"you may be among those it misses.")


def apk_nothing_found(v=None):
    """The whole sentence for tier 1: what it means, then how often it is wrong."""
    base = ('No harmful behaviour was established by static examination. '
            'That is not a finding that the app is safe.')
    measured = apk_measured(v)
    if measured is None:
        return base + ' How often this engine misses malware has not been measured.'
    return f'{base} {measured}'


def network_rates_sentence(n=None):
    """Why a finding is a lead, in the report's own voice, from the rate table."""
    n = n if n is not None else network_figures()
    fired, total = len(n['rules_firing_on_ordinary_traffic']), counts()['rules']
    return (f"Each rule's measured false-alarm rate is printed with its findings. {fired} of the {total} "
            f"detection signals fired on at least one of {n['ordinary_captures']} captures of ordinary "
            f"traffic, so a finding is a reason to look, not a conclusion. Only {n['attack_captures']} "
            f"attack captures were available, and the attack side contains no connection-per-callback "
            f"beacon, so what these rules miss has not been measured.")


def network_nothing_found(n=None):
    n = n if n is not None else network_figures()
    return ('No rule fired. That is not evidence the network was quiet: the rules are tested '
            f"against {n['attack_captures']} attack captures, which is too few to say what they "
            'miss, and an attack that avoids a rule\'s pattern raises nothing.')


# Quotations from NIST SP 800-86 (Kent, Chevalier, Grance, Dang; August 2006),
# read from the published PDF; section numbers are the document's own.
NIST_PHASES = (
    'During collection, data related to a specific event is identified, labeled, recorded, and '
    'collected, and its integrity is preserved. In the second phase, examination, forensic tools '
    'and techniques appropriate to the types of data that were collected are executed to identify '
    'and extract the relevant information from the collected data while protecting its integrity. '
    'Examination may use a combination of automated tools and manual processes. The next phase, '
    'analysis, involves analyzing the results of the examination to derive useful information that '
    'addresses the questions that were the impetus for performing the collection and examination. '
    'The final phase involves reporting the results of the analysis, which may include describing '
    'the actions performed, determining what other actions need to be performed, and recommending '
    'improvements to policies, guidelines, procedures, tools, and other aspects of the forensic process.')
NIST_FALSE_NEGATIVE = 'False Negative: Incorrectly classifying malicious activity as benign.'
NIST_IDS_VALIDATE = ('IDS software does produce false positives, so IDS alerts should be validated.')
NIST_NOT_A_GUIDE = ('The publication is not to be used as an all-inclusive step-by-step guide for '
                    'executing a digital forensic investigation or construed as legal advice.')

ISO_27037_SCOPE = ('guidelines for specific activities in the handling of digital evidence: '
                   'identification, collection, acquisition and preservation of potential digital '
                   'evidence that can be of evidential value')


def standards():
    return [
        {
            'id': 'NIST SP 800-86',
            'title': 'Guide to Integrating Forensic Techniques into Incident Response',
            'authors': 'Kent, Chevalier, Grance, Dang', 'date': 'August 2006', 'status': 'Final',
            'url': 'https://csrc.nist.gov/pubs/sp/800/86/final',
            'verified': True,
            'note': NIST_NOT_A_GUIDE,
            'quotes': [
                {'text': NIST_PHASES, 'where': 'section 3, "Performing the Forensic Process"'},
                {'text': NIST_FALSE_NEGATIVE, 'where': 'Appendix C, Glossary'},
                {'text': NIST_IDS_VALIDATE, 'where': 'section 6.4.2.1, "Data Source Value", on intrusion '
                         'detection software; the same reasoning applies to any automated detection'},
            ],
            'mapping': [
                {'phase': 'Collection',
                 'does': 'Takes custody of a file it is given: hashes it (SHA-256, SHA-1, MD5), keeps '
                         'a sealed copy encrypted at rest, and records every handling in a hash-chained log.',
                 'does_not': 'Acquire from a device. There is no imaging, no write-blocking and no '
                             'chain of custody before the file reaches it. Live capture sniffs the local '
                             'network interface of the machine it runs on and has not been validated as an '
                             'acquisition method.'},
                {'phase': 'Examination',
                 'does': 'Assembles flows from a capture and examines an Android package statically, on the '
                         'sealed copy. A sample is never executed.',
                 'does_not': 'See code fetched, decrypted or generated at runtime, or anything a rule was '
                             'not written for.'},
                {'phase': 'Analysis',
                 'does': 'Raises findings from rules and evidence tiers, each with the threshold, its source '
                         'and, for network rules, the rule\'s measured false-alarm rate.',
                 'does_not': 'Reach a conclusion. Findings are leads for an examiner; a rule that fires on '
                             'ordinary traffic is a reason to look, not a conclusion.'},
                {'phase': 'Reporting',
                 'does': 'Produces an examination report, a custody register, Section 63 certificates and a '
                         'signed case package.',
                 'does_not': 'Decide whether any of it is admissible, or who is qualified to sign Part B.'},
            ],
        },
        {
            'id': 'ISO/IEC 27037:2012',
            'title': 'Guidelines for identification, collection, acquisition and preservation of digital evidence',
            'date': '2012', 'url': 'https://www.iso.org/standard/44381.html',
            'verified': False,
            'note': 'The standard is paywalled and its own page refused a fetch, so its scope is stated from '
                    'published summaries, not from the text. Secondary source.',
            'quotes': [{'text': ISO_27037_SCOPE, 'where': 'as summarised in its published abstract (secondary)'}],
            'mapping': [
                {'phase': 'Preservation',
                 'does': 'Hashes and seals what it is given, encrypts it at rest, logs each handling, and '
                         're-hashes on demand.',
                 'does_not': 'Show that the file was unchanged before it arrived.'},
                {'phase': 'Identification, collection, acquisition',
                 'does': 'Nothing beyond reading a file it is handed.',
                 'does_not': 'Identify devices, collect or acquire from them. These need other tools.'},
            ],
        },
    ]


def cannot(c=None):
    """What the tool does not do, as sentences. The engine's own limits are included verbatim."""
    from apk_engine.report import LIMITS

    c = c or counts()
    return [
        *LIMITS,
        'These rules detect behaviour, not identity. Traffic matching a rule shows a machine acted in a '
        'described way; it does not establish who was at the keyboard.',
        f"{c['heuristic_thresholds']} of the {c['thresholds']} thresholds the network rules compare against "
        'are this project\'s own heuristics, not published figures. Each finding names its threshold and '
        'whether it is one.',
        'The custody log is tamper-evident, not tamper-proof. A hash chain shows a log is consistent; it '
        'cannot show the whole log was not rebuilt before it was signed.',
        f"MITRE ATT&CK identifiers are a shared vocabulary, not a finding of fact. {c['rules_without_attack_identifier']} "
        f"of the {c['rules']} detection signals carry no identifier because no technique honestly describes them.",
        'The clock is the machine\'s own. Where it is not synchronised to a trusted source, timestamps are '
        'machine-relative, and the evidence status says so.',
        'Nothing here has been reviewed by anyone other than its author. It is not accredited, no laboratory '
        'has set acceptance criteria for it, and the validation report is developer-supplied information, not '
        'a validation of any laboratory\'s method.',
    ]


def references():
    """Every source the interface cites, as text — so a printed page still names them."""
    from apk_engine.sources import SOURCES

    items = [{'title': s['title'], 'publisher': s['publisher'], 'date': s['date'], 'url': s['url'],
              'verified': s['verified']} for s in SOURCES.values()]
    return sorted(items, key=lambda i: (i['publisher'], i['title']))


def document():
    v = summary()
    c, n = counts(), network_figures()
    return {
        'validation': v,
        'counts': c,
        'network': n,
        'nothing_found': {'apk': apk_nothing_found(v), 'apk_measured': apk_measured(v),
                          'network': network_nothing_found(n)},
        'cannot': cannot(c),
        'standards': standards(),
        'references': references(),
        'status': ('Developer-supplied testing information, not reviewed by anyone other than its author. '
                   'See validation/VALIDATION_REPORT.md.'),
    }
