# Notice

**NetForensiq** — network forensics and Android malware examination for police
cybercrime investigation.

Copyright (c) 2026 Anbuchelvan Ganesan
Source: <https://github.com/Anbu-00001/NetForensiq>
Licence: MIT — see [LICENSE](LICENSE)

Built for KANAD S.H.I.E.L.D. 2026, the Ahmedabad City Police cybercrime hackathon
run by the Cyber Crime Branch with i-Hub Gujarat.

---

## You are welcome to use this

NetForensiq is open source on purpose. Use it, study it, deploy it, fork it,
build on it, teach with it. The MIT licence permits all of that, commercially or
not, without asking.

It asks for one thing, and that one thing is a legal condition rather than a
courtesy:

> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.

Every source file carries a two-line header naming the licence and the author.
Keep it, and keep [LICENSE](LICENSE), in any copy or derivative — including a
ZIP download, a vendored copy, or a fork.

## If you present work built on this

Fork it, extend it and submit the result anywhere — and say where it started. A
line such as *"built on NetForensiq by Anbuchelvan Ganesan
(github.com/Anbu-00001/NetForensiq)"* is enough.

Presenting this code, or a derivative with the notices removed, as your own
original work is not permitted by the licence, because the licence's only
condition is that the notice stays. Where a competition or course requires
original work, it is also a question for that competition's rules.

This is not a hypothetical concern and it is not left to trust:
[PROVENANCE/](PROVENANCE/) holds a SHA-256 manifest of every source file and an
[OpenTimestamps](https://opentimestamps.org/) proof anchoring that manifest to
the Bitcoin blockchain, which anyone can verify independently of this
repository and of its author. `scripts/provenance_check.py` compares any
suspected copy — a directory, a fork or a ZIP — against that manifest.

## The name

The MIT licence grants rights in the code. It grants no rights in the name
**NetForensiq** or in the author's name. A fork is welcome to exist; it should
not present itself as the original project or imply the author's endorsement.

## Third-party components

NetForensiq depends on, and ships data from, projects under their own licences —
scapy (GPL-2.0-only), androguard and apkInspector (Apache-2.0), Exodus Privacy
tracker signatures (ODbL-1.0), Echap stalkerware indicators (CC-BY-4.0) and
others. Those are listed, with the reasoning behind the licence architecture, in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The copyright notice above
covers NetForensiq's own code and documentation, not those components.

## Responsible use and security

How this tool should and should not be used: [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).
Reporting a vulnerability: [SECURITY.md](SECURITY.md).
Using NetForensiq somewhere? You are not obliged to say so — but a
[deployment report](.github/ISSUE_TEMPLATE/deployment-report.md) is always
appreciated.

*Nothing in this file is legal advice. It records the terms the code is offered
under and the author's intent.*
