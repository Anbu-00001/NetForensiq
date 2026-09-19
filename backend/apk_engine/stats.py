# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
How much a benign-corpus measurement actually licenses us to say.

"Fired on 0 of 31 legitimate apps" does not mean the false-positive rate is
zero. It means the rate is probably below some bound, and with 31 apps that
bound is not small. The report prints the bound next to the count so nobody
reads the count as a guarantee.

The bound is the exact one-sided Clopper–Pearson upper limit: the largest rate
p for which seeing k or fewer firings in n trials still has probability at
least ``alpha``. With k = 0 it reduces to 1 - alpha**(1/n), which is where the
familiar "rule of three" (≈ 3/n at 95%) comes from. Computed by bisection on
the binomial CDF so the engine needs no scipy.
"""

from math import comb


def binomial_cdf(k, n, p):
    """P(X <= k) for X ~ Binomial(n, p)."""
    return sum(comb(n, i) * (p ** i) * ((1 - p) ** (n - i)) for i in range(k + 1))


def upper_bound(k, n, alpha=0.05):
    """
    One-sided exact upper confidence limit on a rate observed as k of n.

    Returns None for n == 0: no measurement bounds nothing, and a number here
    would be invented.
    """
    if n <= 0:
        return None
    if k >= n:
        return 1.0
    if k == 0:
        return 1 - alpha ** (1 / n)
    lo, hi = k / n, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if binomial_cdf(k, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi
