# NetForensiq → Wazuh

Two files that turn NetForensiq's syslog output from something Wazuh can
*receive* into something Wazuh can *search, alert on and group by*.

## Why this exists

NetForensiq already emits RFC 5424 syslog carrying a CEF record, and any
syslog-receiving SIEM takes delivery of it with no code on either side. That
is where most projects stop and call it "SIEM integration".

It is not, quite. Without a decoder the whole line arrives as one string in
`full_log`. An analyst can grep it. They cannot alert on a severity, count
findings by rule, pivot on a technique, or see NetForensiq events in Wazuh's
MITRE ATT&CK view. **A decoder and a ruleset are the difference between an
export format and an integration**, and they are what a SOC engineer means by
the word.

Wazuh was chosen as the target because it is open source, runs offline, and
is the SIEM most likely to actually sit in a police laboratory that cannot
license Splunk or QRadar per-GB.

## Install

```bash
sudo cp decoders/netforensiq_decoders.xml /var/ossec/etc/decoders/
sudo cp rules/netforensiq_rules.xml       /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/decoders/netforensiq_decoders.xml \
                      /var/ossec/etc/rules/netforensiq_rules.xml
sudo /var/ossec/bin/wazuh-control restart
```

Then open a syslog listener in `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.0.0.0/8</allowed-ips>
</remote>
```

and point NetForensiq at it — see `backend/.env.example`, `ALERT_SYSLOG_HOST`
and `ALERT_SYSLOG_PORT`. TCP is worth preferring: the alerting path frames TCP
with RFC 6587 octet counting, so a long finding cannot be silently truncated
at a datagram boundary the way UDP would.

## Check it before you trust it

`sample-events.log` holds one real line per detection this engine can emit,
so the decoder can be proved to work without NetForensiq running:

```bash
sudo /var/ossec/bin/wazuh-logtest < integrations/wazuh/sample-events.log
```

Expect, per line: `netforensiq-cef` as the decoder, `nf_rule` /`nf_severity` /
`nf_title` among the extracted fields, and a rule id in the 1002xx range.

## What it decodes, and what it does not

Decoded: the CEF header — vendor, product, version, rule identifier, title,
CEF severity — plus `cs1`, our own severity word, which the rules key their
alert level off.

Not decoded: the remaining CEF extensions. That is deliberate. They are
conditional — `cs3` appears only when the finding maps to an ATT&CK technique,
`src`/`dst`/`proto` only when there is a flow behind it — and a single regex
with optional groups misaligns Wazuh's `<order>` list the moment one is
absent. A decoder that quietly writes the destination address into the
protocol field is worse than one that does not try. The whole CEF line stays
in `full_log` and remains searchable.

## Alert levels

| NetForensiq severity | Wazuh level | Meaning |
|---|---|---|
| critical | 12 | an analyst is expected to look now |
| high | 10 | an analyst is expected to look today |
| medium | 7 | worth review, not worth a page |
| low | 3 | recorded, not surfaced |

Nothing is set above 12. Wazuh treats 13–15 as attack-in-progress and wires
active response to that band; a forensic tool reading a capture is making a
claim about the past, and a claim about the past must not fire an automated
block.

## The ATT&CK identifiers

Each per-detection rule carries the technique from
`backend/capture/attack_mapping.py` — the same table the platform's own
interface and its ECS output use, so Wazuh's ATT&CK coverage view and ours
cannot disagree.

Three detections carry no `<mitre>` block on purpose. Host corroboration is
our analytic agreeing with itself, a statistical anomaly says traffic was
unusual for this capture rather than what an adversary did, and a blocklist
hit is a claim about an address rather than a technique. Attaching a plausible
identifier to any of them would put a fabricated classification into a SOC's
coverage view, which is worse than a gap in it.

## These files are tested

`backend/capture/tests_wazuh.py` reads *these files*, extracts the regex and
the rule identifiers, and runs them against live output from `to_syslog`. It
fails if the decoder stops matching, if a new detection is added without a
rule, if any level exceeds 12, or if a technique here disagrees with
`attack_mapping.py`.

A decoder that has drifted from its emitter is worse than no decoder: it
installs cleanly, matches nothing, and reports zero alerts — which looks
exactly like a quiet network.
