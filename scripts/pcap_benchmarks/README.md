# PCAP engine benchmarks

The measurements behind [research/153_PCAP_ENGINE_PERFORMANCE.md](../../research/153_PCAP_ENGINE_PERFORMANCE.md).

These are measurement tools, not product code. They exist so the numbers in 153 can be
re-run rather than believed, and so a future change that slows the import path shows up
against a recorded baseline instead of against memory.

Run them from `backend/` with the venv python. Anything that touches the database wants
a throwaway copy, never the working one:

    cp backend/netforensiq.sqlite3 /tmp/bench.sqlite3
    cd backend
    SQLITE_NAME=/tmp/bench.sqlite3 .venv/bin/python ../scripts/pcap_benchmarks/e2e.py <pcap> 150000

| script | answers |
|---|---|
| `profile_stages.py` | where import time goes, stage by cumulative stage |
| `scapy_share.py` | how much of aggregation is scapy DNS and scapy ICMP |
| `e2e.py` | parse vs persist vs detect, as percentages |
| `find_nplus1.py` | which `refresh_from_db` calls a queryset is triggering, and from where |
| `equiv.py` | the `.only()` fix: old vs new, hits compared field by field |
| `dns_compare.py` | `fastdns_proto` vs scapy: speed and byte-equality |
| `icmp_compare.py` | the naive ICMP offset table (fails on types 3/11 — kept as the negative result) |
| `icmp_why.py` | tests the RFC 4884 hypothesis for that failure (disproves it) |
| `icmp_rule.py` | the 128-byte cap rule: 73,935/73,935 identical |
| `combined.py` | both prototypes wired in, end to end, findings compared |
| `orm_fair.py` | Django `bulk_create` vs `executemany`, like for like |
| `fastdns_proto.py` | the original prototype DNS reader (superseded by `capture/fastdns.py`) |
| `icmp_experiment.py` | synthetic probe that located scapy's 128-octet cut |
| `icmp_boundary.py` | the RFC 4884 boundary cases: flat-128 wrong 113/375, rfc4884 rule 0/375 |
| `icmp_layerdep.py` | **the import-order finding**: 0 divergent with `scapy.layers.inet`, 94 with `scapy.all` |
| `divergence.py` | divergence counts for both readers across every capture |
| `dns_phantom.py` | finds the payloads where scapy invents a `www.example.com.` query |
| `findings_impact.py` | whether a payload-definition change moves any *finding* (it did not) |
| `orm_floor.py` | Django ORM cost against the raw SQLite floor |
| `batch_test.py` | bulk_create batch_size sweep (500 is already optimal) |

`icmp_compare.py` is deliberately kept although it is wrong. It is the record of a
shortcut that was 800x faster and would have changed findings, caught by diffing
against scapy — which is the argument for §7 of 153.
