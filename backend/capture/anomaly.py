"""
Statistical anomaly detection — the secondary signal.

Where this sits
---------------
The nine rules in detection.py are the primary engine, and they are
deliberately deterministic: each fires on a stated threshold traceable to a
published source or labelled as our own heuristic. That is what makes a finding
defensible in court — an officer can say *why* the machine flagged something.

This module does something the rules cannot: it finds traffic that is unusual
*for this capture*, without anyone having written a rule for it. That covers
the case the problem statement calls "zero-day or unknown attacks" — behaviour
no signature describes.

The cost is that it cannot cite a threshold. So it is bound by three rules:

  1. **It never issues a finding above MEDIUM.** An anomaly is a reason to
     look, never a conclusion. Only the deterministic rules speak at HIGH or
     CRITICAL.
  2. **It always says which features were unusual, and by how much.** A score
     with no explanation is exactly the black box that the Gujarat High Court's
     April 2026 AI policy is wary of, and that an officer cannot testify to.
     Every finding this module emits names the features and their z-scores.
  3. **It is labelled as statistical, not as a rule.** The method field carries
     `statistical`, the UI shows it differently, and the §63 certificate does
     not rest on it.

Why unsupervised, and why per-session
--------------------------------------
There is no labelled corpus of Indian police packet captures to train on, and a
model trained on somebody else's network encodes somebody else's normal. So the
model is fitted on the capture being analysed: it learns what is ordinary in
*this* traffic and reports what stands apart from it. That is the honest form
of "AI" available here, and it has a real limitation worth stating out loud —
if a capture is entirely malicious, nothing in it looks anomalous.

IsolationForest is used because it isolates outliers by random partitioning
rather than by modelling density, which suits a feature space where the
dimensions have wildly different scales and no Gaussian assumption holds.
"""

import math

import numpy as np

# Features fed to the model, in a fixed order.
#
# Chosen because each is a quantity an investigator would recognise as
# meaningful about a conversation — how much moved, how fast, how regular, how
# random-looking. Deliberately excluded: IP addresses and ports as raw numbers,
# which carry no ordinal meaning and would let the model learn that 10.0.0.9 is
# "greater than" 10.0.0.5.
FEATURES = (
    ('bytes_sent', 'volume sent', True),
    ('bytes_received', 'volume received', True),
    ('packets_sent', 'packets sent', True),
    ('packets_received', 'packets received', True),
    ('duration_seconds', 'conversation length', True),
    ('avg_packet_size', 'average packet size', False),
    ('packets_per_second', 'packet rate', True),
    ('bytes_ratio', 'send/receive imbalance', False),
    ('payload_entropy', 'payload randomness', False),
    ('unique_dst_ports', 'destination ports touched', False),
    ('interval_dispersion', 'timing regularity', False),
    ('dns_query_count', 'DNS lookups', True),
    ('longest_dns_label', 'longest DNS label', False),
)

# Below this many flows the notion of "unusual for this capture" has no
# content — with a handful of conversations everything is both typical and
# atypical. Our own figure: IsolationForest's default subsample is 256, and
# fitting on fewer samples than that means the trees see nearly the whole set
# every time, so isolation stops discriminating.
MIN_FLOWS = 50

# The proportion of flows the model is told to treat as outliers.
#
# This is the one number here that behaves like a threshold, and it is ours,
# not a published figure. Two percent of a capture is a reviewable number of
# leads for one analyst; ten percent is a second job. It is deliberately
# conservative — this signal exists to point, and pointing at everything is the
# same as pointing at nothing.
CONTAMINATION = 0.02

# The most anomalies that will ever be reported from one capture.
#
# Contamination is a *proportion*, and on a week-long server capture 2% of
# 166,093 flows is 3,278 findings — which is not a shortlist, it is a second
# haystack. An officer with a shift and a case can genuinely work through a few
# dozen leads. So the proportion decides what the model considers unusual, and
# this decides how many of them are put in front of a person: the strongest by
# isolation score, with the count of those held back reported honestly rather
# than silently dropped.
#
# Our own figure. It is a working-day judgement, not a statistical one.
MAX_FINDINGS = 50

# How far from the median a feature must sit, in robust standard deviations,
# before it is named as a reason. Below this it is noise dressed as evidence.
EXPLAIN_Z = 2.0

# The magnitude reported when a feature is constant across every other flow
# and this one differs. It is a label meaning "categorically different", not a
# measurement — the true ratio is undefined, and printing 10^17 would state a
# precision that does not exist. Chosen to sort above ordinary outliers.
CONSTANT_FEATURE_Z = 99.0

# Scale factor converting median absolute deviation to a standard-deviation
# equivalent for a normal distribution. Standard constant, not a tuned value.
MADM_TO_SIGMA = 1.4826

RULE_ID = 'ANOMALY_STATISTICAL'


def _vector(flow):
    """One flow as numbers, log-compressed where the range demands it."""
    row = []
    for name, _label, log_scale in FEATURES:
        value = float(getattr(flow, name, 0) or 0)
        # Counts and volumes span several orders of magnitude in one capture: a
        # DNS lookup is 80 bytes and a file transfer is 80 MB. Without
        # compression the model would see only "big transfer / everything
        # else" and rediscover the largest flow every time.
        row.append(math.log1p(max(value, 0.0)) if log_scale else value)
    return row


def _robust_z(matrix):
    """
    Z-scores computed from the median and MAD rather than mean and stddev.

    The mean of a feature is dragged by the very outliers being looked for, so
    a conventional z-score understates exactly the values that matter. The
    median does not move.

    Two fallbacks, because MAD reaches zero more often than intuition suggests.
    On a capture where most conversations are identical — which is exactly what
    automated traffic looks like — more than half the values sit on the median
    and the MAD is 0. Dividing by that would discard the one flow that differs,
    which is the flow worth seeing. So:

      MAD zero      → use the standard deviation, which is non-zero whenever
                      any value differs at all.
      stddev zero   → the feature is genuinely constant, and a value departing
                      from a constant is a step change rather than a matter of
                      degree. It is reported at a capped magnitude rather than
                      as an infinity, because "unusually high" is the claim
                      being made and a z of 10^17 states a precision that does
                      not exist.
    """
    median = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - median), axis=0) * MADM_TO_SIGMA

    spread = np.where(mad < 1e-9, matrix.std(axis=0), mad)
    constant = spread < 1e-9

    # Guard the division first, then overwrite the constant columns, so no
    # divide-by-zero warning is emitted on the way.
    safe = np.where(constant, 1.0, spread)
    z = (matrix - median) / safe

    if constant.any():
        deviation = matrix[:, constant] - median[constant]
        z[:, constant] = np.sign(deviation) * np.where(
            np.abs(deviation) > 0, CONSTANT_FEATURE_Z, 0.0,
        )
    return z


def explain(row_z):
    """
    Which features made this flow stand out, strongest first.

    This is the part that makes the signal usable. "Anomaly score -0.71" tells
    an officer nothing; "sent 40x more than a typical conversation here, and at
    an unusually steady rhythm" tells them what to look at.
    """
    reasons = []
    for index, (_name, label, _log) in enumerate(FEATURES):
        z = row_z[index]
        if not np.isfinite(z) or abs(z) < EXPLAIN_Z:
            continue
        reasons.append({
            'feature': label,
            'z_score': round(float(z), 2),
            'direction': 'unusually high' if z > 0 else 'unusually low',
        })
    reasons.sort(key=lambda r: abs(r['z_score']), reverse=True)
    return reasons


def score_session(session, contamination=CONTAMINATION):
    """
    Fit on this session's flows and return the outliers, each with its reasons.

    Returns (results, explanation). `results` is a list of dicts; `explanation`
    is a sentence for the audit trail and the UI saying what was done, or why
    nothing was.
    """
    flows = list(session.flows.all())

    if len(flows) < MIN_FLOWS:
        return [], (
            f'Not run: {len(flows)} flows is below the minimum of {MIN_FLOWS}. '
            f'With fewer conversations than that, "unusual for this capture" '
            f'has no meaning.'
        )

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return [], 'Not run: scikit-learn is not installed.'

    matrix = np.array([_vector(f) for f in flows], dtype=float)
    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)

    # random_state is fixed so the same capture yields the same findings on
    # every run. An analysis that gives different answers to the same evidence
    # on Tuesday than on Monday cannot be put before a court.
    forest = IsolationForest(
        contamination=contamination,
        random_state=0,
        n_estimators=200,
    )
    predictions = forest.fit_predict(matrix)
    scores = forest.score_samples(matrix)
    z_matrix = _robust_z(matrix)

    results = []
    for index, flow in enumerate(flows):
        if predictions[index] != -1:
            continue
        reasons = explain(z_matrix[index])
        if not reasons:
            # The model isolated it but no single feature is far enough from
            # the middle to name. An unexplainable flag is exactly what this
            # module promised not to emit, so it is dropped.
            continue
        results.append({
            'flow': flow,
            'score': round(float(scores[index]), 4),
            'reasons': reasons,
        })

    # Strongest isolation first, so a cap keeps the most anomalous.
    results.sort(key=lambda r: r['score'])
    flagged = len(results)
    suppressed = max(flagged - MAX_FINDINGS, 0)
    results = results[:MAX_FINDINGS]

    explanation = (
        f'Fitted on {len(flows):,} flows from this capture; '
        f'{flagged:,} were isolated as unusual and explainable '
        f'(contamination {contamination:.0%}).'
    )
    if suppressed:
        explanation += (
            f' Reporting the {MAX_FINDINGS} most anomalous — {suppressed:,} '
            f'weaker ones are held back, because a list nobody can work '
            f'through is not a shortlist. Lower the contamination setting to '
            f'narrow what the model treats as unusual.'
        )

    return results, explanation
