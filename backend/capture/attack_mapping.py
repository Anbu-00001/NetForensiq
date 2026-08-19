"""
Mapping findings to MITRE ATT&CK.

Why bother
----------
"Automated attack classification" is a stated bonus objective, and ATT&CK is
the vocabulary every SOC, vendor and threat report already shares. A finding
labelled T1071.004 can be looked up, compared against other tools' output, and
discussed with someone who has never used this platform. That is worth more
than a label only we understand.

The rule this module is written under
--------------------------------------
**A wrong technique ID is worse than none.** It is the kind of claim a
technical judge or a SOC analyst checks in ten seconds, and getting it wrong
discredits the findings that *are* right. So:

  * every mapping below was checked against attack.mitre.org and carries its
    URL;
  * where the choice depends on the finding, it is decided per finding from
    evidence the rule already recorded — never hardcoded to one branch;
  * and two of our ten rules are mapped to **nothing**, deliberately, because
    ATT&CK has no technique that honestly describes them.

The two that do not map
------------------------
`HOST_CORROBORATED` is a correlation pass over other findings, not a detector —
it observes that several rules agree about one machine. ATT&CK describes
adversary behaviour, not an analytic's confidence in itself.

`ANOMALY_STATISTICAL` is an isolation score. It says traffic was unusual for
this capture, which is not a claim about what an adversary did. Forcing either
into a technique would be inventing a classification to fill a column.
"""

# Tactics, by their ATT&CK identifiers.
TA_RECONNAISSANCE = ('TA0043', 'Reconnaissance')
TA_DISCOVERY = ('TA0007', 'Discovery')
TA_COMMAND_AND_CONTROL = ('TA0011', 'Command and Control')
TA_EXFILTRATION = ('TA0010', 'Exfiltration')

BASE_URL = 'https://attack.mitre.org/techniques/'


def _technique(tid, name, tactic, note=''):
    """One technique, with the link a reader can check it against."""
    return {
        'id': tid,
        'name': name,
        'tactic_id': tactic[0],
        'tactic': tactic[1],
        'url': f'{BASE_URL}{tid.replace(".", "/")}/',
        'note': note,
    }


# Techniques referenced below, defined once so an id and its name cannot drift
# apart across branches.
T1071 = _technique(
    'T1071', 'Application Layer Protocol', TA_COMMAND_AND_CONTROL,
    'ATT&CK does not separate periodic beaconing from intra-session keepalive; '
    'both cadences are the same technique at its granularity.',
)
T1071_004 = _technique(
    'T1071.004', 'Application Layer Protocol: DNS', TA_COMMAND_AND_CONTROL,
    'ATT&CK has no DNS-exfiltration technique distinct from this one.',
)
T1572 = _technique('T1572', 'Protocol Tunneling', TA_COMMAND_AND_CONTROL)
T1095 = _technique(
    'T1095', 'Non-Application Layer Protocol', TA_COMMAND_AND_CONTROL,
    "ICMP is named explicitly on this technique's own page.",
)
T1571 = _technique('T1571', 'Non-Standard Port', TA_COMMAND_AND_CONTROL)
T1046 = _technique(
    'T1046', 'Network Service Discovery', TA_DISCOVERY,
    'Applies when the scan originates inside the monitored network.',
)
T1595_001 = _technique(
    'T1595.001', 'Active Scanning: Scanning IP Blocks', TA_RECONNAISSANCE,
    'Applies when the scan originates outside the monitored network.',
)
T1048 = _technique('T1048', 'Exfiltration Over Alternative Protocol', TA_EXFILTRATION)
T1048_003 = _technique(
    'T1048.003',
    'Exfiltration Over Unencrypted Non-C2 Protocol', TA_EXFILTRATION,
    'The sub-technique is chosen only when the channel is known not to be TLS; '
    'guessing between the symmetric and asymmetric variants would be invention.',
)
T1041 = _technique(
    'T1041', 'Exfiltration Over C2 Channel', TA_EXFILTRATION,
    'Preferred when the same host also shows beaconing — the data is leaving '
    'over the channel already identified as command and control.',
)

# Rules with no honest mapping. Listed rather than omitted, so the absence is a
# recorded decision and not an oversight someone later "fixes" by guessing.
UNMAPPED = {
    'IOC_FEED_MATCH': (
        'A match against a third-party blocklist. ATT&CK classifies adversary '
        'behaviour; "this address appears on a list" is a claim about the '
        'address, not about a technique. The feed entry often names a malware '
        'family, which is carried in the finding, but a family is not a '
        'technique and mapping one to the other would be invention.'
    ),
    'HOST_CORROBORATED': (
        'A correlation over other findings, not a detector. ATT&CK describes '
        'adversary behaviour, not an analytic agreeing with itself.'
    ),
    'ANOMALY_STATISTICAL': (
        'An isolation score. "Unusual for this capture" is not a claim about '
        'what an adversary did.'
    ),
}


def classify(detection, beaconing_hosts=frozenset()):
    """
    The ATT&CK techniques for one finding, as a list.

    Empty for the two rules that do not map, and for anything unrecognised —
    an unknown rule getting a plausible technique attached is exactly the
    failure this module exists to avoid.

    Some findings map to more than one technique. ICMP tunnelling is genuinely
    both T1572 and T1095; they are not alternatives, and ATT&CK does not treat
    them as mutually exclusive.

    `beaconing_hosts` is the set of addresses that a beacon rule fired on in
    the same capture. It changes one answer: data leaving a host already
    identified as talking to a controller is exfiltration *over the C2
    channel* (T1041), not over an alternative protocol (T1048). That is
    host-level context a single finding does not carry, so the caller supplies
    it — `classify_session` below does. Omitted, the mapping falls back to the
    safer, less specific technique rather than guessing.
    """
    rule = detection.rule_id
    evidence = detection.evidence if isinstance(detection.evidence, dict) else {}

    if rule in UNMAPPED:
        return []

    if rule in ('C2_BEACON_PERIODIC', 'C2_BEACON_KEEPALIVE'):
        return [T1071]

    if rule.startswith('DNS_TUNNEL_'):
        # T1071.004 rather than an Exfiltration-tactic technique, because it is
        # the technique ATT&CK itself names for data over DNS. Our own rule
        # category says "exfiltration"; ATT&CK files this under command and
        # control. The tension is real and is recorded rather than resolved by
        # picking whichever looks tidier.
        return [T1071_004, T1572]

    if rule == 'RECON_PORT_SCAN':
        # Genuinely bimodal, and the rule already recorded which case it is.
        # A scan from outside is reconnaissance; a scan from inside is an
        # intruder mapping the network they are already on. Those are different
        # tactics and reporting one as the other misleads an analyst.
        inside = evidence.get('source_is_internal')
        if inside is True:
            return [T1046]
        if inside is False:
            return [T1595_001]
        # Unknown provenance: report the parent situation honestly by giving
        # both, rather than choosing on a coin toss.
        return [T1595_001, T1046]

    if rule == 'EXFIL_VOLUME_ASYMMETRY':
        if detection.subject_ip and detection.subject_ip in beaconing_hosts:
            return [T1041]
        # .003 is the unencrypted variant. It is claimed only when the channel
        # is known not to be TLS; choosing between the symmetric (.001) and
        # asymmetric (.002) variants would require knowing the cipher, which
        # this tool does not, so the parent is used instead of a guess.
        if evidence.get('is_tls') is False:
            return [T1048_003]
        return [T1048]

    if rule == 'ICMP_TUNNEL_OVERSIZED':
        return [T1572, T1095]

    if rule == 'COVERT_CHANNEL_UNKNOWN_PORT':
        return [T1571]

    return []


def beaconing_hosts_in(session):
    """Addresses a beacon rule fired on, for the T1041/T1048 decision."""
    return set(
        session.detections
        .filter(rule_id__startswith='C2_BEACON_', subject_ip__isnull=False)
        .values_list('subject_ip', flat=True)
    )


def classify_session(session):
    """
    Classify every finding in a session, with the host context applied.

    Returns {detection_id: [technique, …]}.
    """
    hosts = beaconing_hosts_in(session)
    return {
        detection.id: classify(detection, hosts)
        for detection in session.detections.all()
    }


def describe(detection, beaconing_hosts=frozenset()):
    """
    One line for a report or the interface, or a sentence saying why there is
    none.
    """
    techniques = classify(detection, beaconing_hosts)
    if not techniques:
        reason = UNMAPPED.get(
            detection.rule_id,
            'No MITRE ATT&CK technique is claimed for this finding.',
        )
        return f'Not classified under ATT&CK. {reason}'
    return ' · '.join(
        f'{t["id"]} {t["name"]} ({t["tactic"]})' for t in techniques
    )
