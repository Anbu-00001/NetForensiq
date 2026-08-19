# 130 — Things only you can do

Everything in this file needs a human: a decision, a machine, a credential, or
a conversation with the organisers. Nothing here can be closed by writing code.

Kept current as work lands. Last updated after the case-management,
at-rest-encryption, alert-delivery and session-reconstruction work.

---

## A. Before the event — blocking

| # | Task | Why it blocks | Time |
|---|---|---|---|
| A1 | Run `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f backend/.venv/bin/python)` on the demo laptop | Live capture and the phone bridge cannot open a raw socket without it. Nothing in the app can grant this to itself. | 1 min |
| A2 | Pick **one** demo path — Docker or the offline bundle — and rehearse it end to end at least twice | Both work. Deciding on the day is how a demo fails. | 30 min |
| A3 | If demoing via Docker: put a real `SECRET_KEY` and `DB_PASSWORD` in `.env` | `docker-compose.yml` fails closed on `${SECRET_KEY:?}`. It will not start without them, by design. | 5 min |
| A4 | **Escrow the evidence encryption key.** After the first ingest a key file appears at `backend/.evidence.key` (mode 600). Copy it somewhere that is not the demo laptop. | Losing it destroys every encrypted exhibit. There is no recovery path and there is not meant to be one. See `backend/evidence/crypto.py`. | 5 min |
| A5 | Decide whether the demo runs with encryption on or off (`EVIDENCE_ENCRYPTION=off`) | On is the default and is the stronger story. Off removes A4 as a risk. Either is defensible; pick before the day, not during. | — |
| A6 | **Run `./scripts/save_airgap_images.sh` on a connected machine and carry the output.** | The container runs offline; it does not *build* offline. `docker compose up --build` on an air-gapped machine cannot work, and plain `docker compose up` fails pulling `postgres:17-alpine` unless it was saved too. A build attempt already failed once here on a transient Docker Hub error — do not leave this to the day. | 15 min |

## B. Decisions only you can make

| # | Question | The options | My recommendation |
|---|---|---|---|
| B1 | **Gujarati PDFs.** ReportLab 4.4's HarfBuzz shaping is experimental and ReportLab's own notes decline to promise correct rendering for Indic scripts. | (a) Keep certificates English-only and say why. (b) Move Gujarati-bearing documents to WeasyPrint. | (a) for the hackathon. A certificate that renders Gujarati *wrongly* is worse than one that does not attempt it — and the correct statute to cite for Gujarat is the **Gujarat Official Languages Act 1960**, not the Official Languages Act 1963, which covers Hindi and English. |
| B2 | **How you answer "do you integrate with CCTNS/ICJS?"** | — | "We produce what eForensics consumes, from data entered once. The connection is an authorisation, not an engineering problem." Then show the FSL forwarding letter. |
| B3 | **Whether to ask the organisers if an ICJS/CCTNS sandbox exists for teams** | Asking costs nothing and the answer is useful either way. | Ask. If one exists it is a large, cheap win; if not, B2 is already the honest answer. |
| B4 | **Whether MITRE ATT&CK IDs go on the slides** | They are implemented and verified against attack.mitre.org. | Yes — and say that two of the ten rules map to *nothing*, deliberately. That is the slide a judge remembers. |
| B6 | **Whether the pitch leads with the tiered deployment diagram or with the certificate** | Diagram answers "is it scalable/centralised?". Certificate answers "is it admissible?". | Certificate. It is the harder thing to build and the one nobody else will have. Keep the diagram as the answer to the scalability question when it comes. |
| B5 | **Whether to demo the phone-capture bridge** | It works over USB with `adb` and PCAPdroid, but depends on the venue letting you plug a phone in and on A1 being done. | Have it ready, lead with the pcap path. |

## C. Worth doing if there is time

| # | Task |
|---|---|
| C1 | Rehearse the answer to "is this tamper-proof?" — the honest answer is **tamper-evident**, and the system says so in its own copy. Being the team that corrects the question is a good look. |
| C2 | Have one real (non-synthetic) pcap ready. Everything demo-generated is watermarked `DEMONSTRATION DATA` on purpose, and a judge will notice. |
| C3 | Print one Section 63 certificate and one s.193(3)(i) custody register on paper. Passing physical documents around a table lands better than a screen. |
| C4 | Decide who on the team answers legal questions and who answers technical ones. |

---

## Answered — no longer open

- ~~Live CCTNS/ICJS integration~~ — researched and settled. Access needs NCRB plus a state NIC coordinator's firewall clearance; no code opens that door. The artefact-producing half is built instead (`backend/evidence/fsl_forwarding.py`). See B2.
- ~~Whether the Gujarat HC §63(4) citation was fabricated~~ — verified genuine. A prior agent's challenge searched party names rather than opening the URL.
- ~~Which palette~~ — white/grey/black with a single cyan accent, `frontend/src/theme/tokens.js`. Contrast is recomputed from source on every run by `scripts/check_palette.py`.
