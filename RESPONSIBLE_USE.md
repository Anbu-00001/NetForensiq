# Responsible use

NetForensiq captures network traffic, reads other people's communications
metadata, and examines malware. Those are powerful things to put in anyone's
hands, and this page says plainly how the tool is meant to be used.

## What this page is, legally

**It is guidance, not a licence term.** NetForensiq is released under the MIT
licence, which places no restriction on how the software is used, and this page
does not add one. It records the author's intent and describes the legal
position a user is already in — obligations that come from the law, not from
this repository.

## What it is for

Authorised investigation: police cybercrime units, forensic laboratories,
incident responders and security teams examining networks and devices they are
entitled to examine, and people learning to do that work.

## What it is not for

- **Capturing traffic you are not authorised to capture.** Intercepting
  communications or accessing systems without authority is an offence in most
  jurisdictions, including under India's Information Technology Act, 2000.
  Having a tool that can do it is not authority to do it.
- **Monitoring a person** — a partner, an employee, a family member — without
  lawful authority. That is the stalkerware use case, and the engine is built to
  *detect* stalkerware, not to be it.
- **Handling live malware outside the sandbox.** The corpus scripts keep samples
  encrypted and examine them only in an isolated container for a reason. Do not
  decrypt samples onto a normal filesystem, and never onto a shared or synced one.
- **Treating a finding as a verdict.** Every result states its evidence tier,
  the measured false-positive bound behind it, and what was not examined. "No
  harmful behaviour established" is not "safe", and "built to evade inspection"
  is evidence of concealment, not of what was concealed.

## Guardrails the tool enforces

These are properties of the code, not requests:

- **Separation of duties.** Four roles — Admin, Investigator, FSL/Examiner,
  Viewer. The investigator and the examiner are different roles so that the two
  halves of a BSA 2023 s.63(4) certificate are signed by two people who could
  not have done each other's job.
- **Communication content is gated** behind its own permission, separately from
  the metadata an investigator triages.
- **Evidence is sealed by hash.** An exhibit is recorded with its SHA-256 at
  intake and verified against it, so an altered file is detectable.
- **Offline by design.** Analysis needs no cloud service. The code makes exactly
  two kinds of outbound connection, both at the operator's direction: webhooks to
  alert sinks the operator configures (`capture/alerting.py`), and the reference
  data refresh, which runs only when invoked (`apk_engine/refresh_data.py`). The
  web interface loads nothing from outside the deployment. There is no telemetry,
  and there will not be: a forensic tool that reports on its users would break
  the one guarantee an investigation needs from it.

## If you are publishing results

Say what the tool measured and what it did not. The research notes in
[research/](research/) record every detection rate with its confidence interval,
corpus and limits; a figure quoted without those is not the figure that was
measured.
