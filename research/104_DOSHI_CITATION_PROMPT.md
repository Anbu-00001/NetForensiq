# 104 — Single-target prompt: find a primary citation for the Doshi §63(4) ruling

This is the only research gap left that a panel could expose live and that no
amount of further work by us can close. It is worth one dedicated pass.

**What we have**: a holding, reported by one legal-news aggregator, twice.
**What we lack**: a case name, a case number, a bench date, or any primary text.
**What we must never do**: state a citation we have not read.

Two independent search passes failed. The searches ruled out three candidate
cases and confirmed LiveLaw's May 2026 Gujarat HC digest does not list it. So
this prompt is not "go and search" — it is "search the places we could not
reach, and rule the thing in or out."

Run it **separately** in ChatGPT (browsing on), Gemini and Grok. They index
different corpora. Where two agree and one dissents, the dissent is the signal.
Save replies as `research/105_chatgpt_doshi.md`, `106_gemini_doshi.md`,
`107_grok_doshi.md`.


---

## ✅ RESOLVED — 19 August 2026

**FOUND. Cite it.**

> ***Kshitijbhai Manubhai Patel & Ors. v. Dilipbhai Laxmanbhai Kanani & Anr.***
> R/Special Civil Application No. 120 of 2023 (C/SCA/120/2023)
> Gujarat High Court — Hon'ble Mr. Justice J.C. Doshi
> Reserved 30 April 2026, pronounced **8 May 2026**
> [indiankanoon.org/doc/19060776](https://indiankanoon.org/doc/19060776/)

ChatGPT and Gemini were run separately and returned the **same case number, the
same URL and the same verbatim quotes** — the decision rule below calls that a
citation, not a coincidence. The judgment was then opened and read directly
before anything was written into [research/99](99_GUJARAT_FIT.md) or PROGRESS.md.

### Challenged 19 Aug 2026 — and it held

A reviewing agent reported that this citation was fabricated: that the real
dispute between these parties is a 2016 matter (SCA 743/2016) before Justice
S.H. Vora, plus a 2018 bail matter before Justice R.P. Dholaria, and that the
Indian Kanoon link "doesn't resolve to anything matching".

**That report is wrong, and it is wrong in an instructive way**: it searched
rather than opened the document. The parties are long-running litigants, so a
search on their names surfaces the earlier stages of the same feud and buries
the 2026 order.

The page was re-fetched over raw HTTP — no model in the loop, no summarisation
— and the judgment text itself says:

```
HTTP 200, 109,041 bytes
<TITLE>Kshitijbhai Manubhai Patel vs Dilipbhai Laxmanbhai Kanani on 8 May, 2026</TITLE>

Gujarat High Court
NEUTRAL CITATION  C/SCA/120/2023   CAV JUDGMENT DATED: 08/05/2026
Reserved On  : 30/04/2026
Pronounced On: 08/05/2026
IN THE HIGH COURT OF GUJARAT AT AHMEDABAD
R/SPECIAL CIVIL APPLICATION NO. 120 of 2023
HONOURABLE MR. JUSTICE J. C. DOSHI
KSHITIJBHAI MANUBHAI PATEL & ORS. Versus DILIPBHAI LAXMANBHAI KANANI & ANR.
```

Both phrases are present verbatim in the body:

> "…upheld the ratio in Anvar PV (supra) and held issuance of certificate under
> section 65-B(4) is **a condition precedent** for admissibility of
> computer-generated secondary evidence. It cannot be supplemented through oral
> evidence."

> "…the impugned order passed by the trial Court, ignoring the aforesaid
> provision having the value of a binding precedent, dehors the same and is **a
> patent illegality**, and therefore … the impugned order is required to be set
> aside…"

So is the FSL order it set aside:

> "It is ordered that the audio tape submitted in the current suit shall be
> sealed in the presence of the Registrar and sent through a Special Bailiff to
> the F.S.L. (Forensic Science Laboratory), Gandhinagar for examination."

The document carries the Gujarat High Court registry's own upload stamp —
"Uploaded by Raj Subhash Dhobi (HC01779) on Wed May 13 2026" — and runs to 21
pages.

**Check it yourself in ten seconds**, which is the right response to a challenge
like this:

```bash
curl -sL https://indiankanoon.org/doc/19060776/ | grep -o "J. C. DOSHI\|condition precedent\|patent illegality"
```

**Two things worth taking from the judgment that were not in the original
report:**

- It cites **Parulben W/o Mahendrabhai Rameshbhai Godhani v. State of Gujarat,
  2026 (0) JX(Guj) 73** — a second Gujarat High Court authority holding the
  §65B(4) certificate a prerequisite. A spare, if anyone disputes the first.
- Para 8 says: *"If it is a primary document, it has to be produced along with
  the **hash value**."* A Gujarat judge, this year, naming the hash as what a
  primary electronic document must arrive with. That is the single most useful
  sentence in the judgment for this project and it was missed on the first pass.

**The holding**: a §65B(4) certificate "is a condition precedent for
admissibility of computer-generated secondary evidence. It cannot be
supplemented through oral evidence." In its absence "the Court cannot take
decision in regards to admissibility of electronic evidence."

**One precision to carry to the slide.** The judgment does *not* say that
sending evidence to FSL is illegal. It says admissibility must be decided
*first*, and that the trial court's order — which sealed the audio tape and
sent it to FSL Gandhinagar without deciding the certificate question — was "a
patent illegality." The aggregator headline that first surfaced this case
collapses those two statements into one. Say the judgment's version.

The full replies from both models are kept verbatim at the end of this file.

---

## The prompt

```
I need to establish whether a specific Gujarat High Court judgment exists, and
if it does, get its citation. This is for a document that will be shown to
serving police officers, so a fabricated or guessed citation is far worse than
an honest "not found". Do not synthesise a case name from the description
below. Do not offer a "likely" or "probably cited as" citation. If you cannot
open a page and read the case name on it, the answer is NOT FOUND.

THE JUDGMENT I AM LOOKING FOR

Reported holding: a certificate under section 65B(4) of the Indian Evidence Act
1872 / section 63(4) of the Bharatiya Sakshya Adhiniyam 2023 is a "condition
precedent" to a court considering electronic evidence at all; and a trial court
that sent an audio recording to a Forensic Science Laboratory BEFORE ruling on
whether the certificate requirement was met committed "patent illegality".

Attributed to: Justice J.C. Doshi, Gujarat High Court.
Reported date: on or around 8 May 2026.

Underlying facts as reported: a suit for specific performance of an ORAL
agreement to sell a bungalow. The plaintiff sought to rely on a tape/audio
recording of a telephone conversation as evidence of the oral agreement. A
dispute arose over admissibility. The trial court referred the recording to FSL.
The High Court set that aside.

WHAT HAS ALREADY BEEN CHECKED — DO NOT REPEAT THESE

- Source of the report: lawyerenews.com, two articles, both aggregator pieces
  with no case number:
  https://lawyerenews.com/legal_detail/secondary-electronic-evidence-inadmissible-without-mandatory-certificate-sending-to-fsl-before-deciding-admissibility-is-patent-illegality-gujarat-high-court
  https://lawyerenews.com/legal_detail/fsl-probe-before-electronic-evidence-meets-section-65b-admissibility-standards-gujarat-high-court
- LiveLaw's Gujarat High Court monthly digest for May 2026: checked directly,
  does not list it.
- These three 2026 Gujarat HC cases were examined and RULED OUT — they do not
  match the fact pattern. Do not return any of them:
    - Punabhai Bijalbhai v. State of Gujarat, 20 Mar 2026
      https://indiankanoon.org/doc/174592327/
    - Shreeji Enterprise v. State of Gujarat, 1 Apr 2026
      https://indiankanoon.org/doc/74687407/
    - State of Gujarat v. Bharatbhai Malubhai Gohil, 24 Apr 2026
      https://indiankanoon.org/doc/29423004/

WHERE TO LOOK, IN THIS ORDER

1. Gujarat High Court's own site, gujarathighcourt.nic.in — the daily
   judgment/order lists and the case-status search. Look at 5–12 May 2026.
   A civil-side interlocutory matter of this kind would most likely be a
   Special Civil Application, a Civil Revision Application, or an application
   under Article 227. Search those case types for that window.
2. indiankanoon.org — search the distinctive language rather than the facts:
   "condition precedent" together with "65B" and "Gujarat" in 2026; and
   separately "patent illegality" with "Forensic Science Laboratory".
   Indian Kanoon's own date filter for 2026 is more reliable than a web search.
3. LiveLaw, Bar & Bench, SCC Online Blog, Verdictum, Live Law Gujarat tag —
   search "Doshi" plus "65B" plus 2026.
4. Judgments authored by Justice J.C. Doshi in April–June 2026 generally. If
   you can list them, do — the report's date may be off by a few weeks even if
   the judgment is real. Confirm first that a sitting judge of the Gujarat High
   Court is named J.C. Doshi, and give his full name as the court lists it.
5. The e-Courts / National Judicial Data Grid portal for Gujarat High Court,
   if you can reach it.

WHAT I NEED BACK

Answer in exactly this form.

VERDICT: one of
  FOUND        — you opened a page that names the case
  NOT FOUND    — you searched and it is not there
  BLOCKED      — a source you needed would not load; name which

If FOUND:
  Case name (as written on the source):
  Case number:
  Date of judgment:
  Bench:
  URL you opened:
  Verbatim quote containing "condition precedent":
  Verbatim quote containing "patent illegality":
  Does the fact pattern match (oral bungalow sale agreement, audio recording of
  a phone call, FSL referral)? Quote the line that shows it.

If NOT FOUND:
  List every source you actually searched and what query you used in each.
  Say specifically whether Justice J.C. Doshi exists as a Gujarat High Court
  judge, and whether the Gujarat HC site was reachable.
  Then answer: is there a DIFFERENT, verifiable Indian judgment from 2024–2026
  that holds the section 65B(4)/63(4) certificate to be a condition precedent
  or mandatory prerequisite to admissibility? Give its full citation and a link.
  Prefer the Supreme Court or a High Court. I would rather cite a real case
  with a slightly weaker fit than an unverifiable one with a perfect fit.

Finally, rate your own confidence 0–100 that this specific judgment exists, and
say what would change your mind.
```

---

## How to read the replies

| Outcome | What to do with it |
|---|---|
| Two or three models return the **same case number** and it resolves on a primary site | Cite it. Read the judgment first. |
| Models return **different** case numbers | Treat all as unverified. This is the classic signature of fabrication. |
| All return NOT FOUND | Drop it entirely from the deck. Open on *Pooranmal v. State of Rajasthan* (2026 INSC 217) instead — verified, Supreme Court, same principle, and already in [research/99](99_GUJARAT_FIT.md). |
| A model offers a substitute case | Open the link yourself before it goes anywhere near a slide. |

**The fallback is already strong.** *Pooranmal* is a verified Supreme Court
ruling on mandatory §65B certification and chain of custody. The Doshi ruling
would be better only because it is Gujarat and this year. That is a
presentation upgrade, not a dependency — nothing in the product rests on it.




Gemini:

VERDICT: FOUND

Case name (as written on the source): Kshitijbhai Manubhai Patel vs Dilipbhai Laxmanbhai Kanani
Case number: R/SPECIAL CIVIL APPLICATION NO. 120 of 2023
Date of judgment: 08/05/2026
Bench: HONOURABLE MR. JUSTICE J. C. DOSHI
URL you opened: https://indiankanoon.org/doc/19060776/

Verbatim quote containing "condition precedent":

"(supra) upheld the ratio in Anvar PV (supra) and held issuance of certificate under section 65-B(4) is a condition precedent for admissibility of computer-generated secondary evidence."

Verbatim quote containing "patent illegality":

"In exposition of above legal situation, in the considered opinion of this Court, the impugned order passed by the trial Court, ignoring the aforesaid provision having the value of a binding precedent, dehors the same and is a patent illegality, and therefore, without entering further merits of the case, the impugned order is required to be set aside and the application is required to be remanded back to the learned trial Court to decide the same afresh, after following the aforesaid binding precedent."

Does the fact pattern match (oral bungalow sale agreement, audio recording of a phone call, FSL referral)? Quote the line that shows it:
Yes, the fact pattern matches in every detail.

Line showing oral bungalow sale agreement:

"2. The brief facts of the case are that, the respondents - original plaintiffs have instituted a Special Civil Suit No. 187 of 2016 against the petitioners - defendants claiming, specific performance of oral agreement alleged to have been entered into with the petitioners for the sale of the immovable property consisting of bungalow situated in Muni Hemchandra Acharya Co-operative Housing Society, known as 'Bhikhubhai Bungalows'."

Line showing audio recording of talk/call:

"2.2 The respondents - plaintiffs claim that they recorded the talks between the parties, which establish that the concluded contract was executed."

Line showing FSL referral:

"2.9 Pursuant to the aforesaid order, the application at Exhibit-119 was again decided by the order dated 30.12.2022. The 2nd Additional Senior Civil Judge, Ahmedabad Rural, passed the following order:- 'It is ordered that the audio tape submitted in the current suit shall be sealed in the presence of the Registrar and sent through a Special Bailiff to the F.S.L. (Forensic Science Laboratory), Gandhinagar for examination.'"

CONFIDENCE: 100 / 100
What would change my mind: Nothing regarding existence or citation; the judgment is verifiably present in official records and database mirrors, authored by Justice J.C. Doshi on 8 May 2026 in Kshitijbhai Manubhai Patel v. Dilipbhai Laxmanbhai Kanani (Special Civil Application No. 120 of 2023). Only a formal recall, review order, or expungement by the High Court setting aside this specific judgment would alter its legal standing.


Chatgpt:

VERDICT: FOUND

Case name (as written on the source):
KSHITIJBHAI MANUBHAI PATEL & ORS. Versus DILIPBHAI LAXMANBHAI KANANI & ANR.

Case number:
R/SPECIAL CIVIL APPLICATION NO. 120 of 2023 — the judgment header also identifies it as C/SCA/120/2023.

Date of judgment:
8 May 2026. Reserved on 30 April 2026; pronounced on 8 May 2026.

Bench:
HONOURABLE MR. JUSTICE J. C. DOSHI (single judge). The Gujarat High Court's own site also currently lists Hon'ble Mr. Justice J.C. Doshi as a serving Gujarat High Court judge.

URL you opened:
https://indiankanoon.org/doc/19060776/

Verbatim quote containing "condition precedent":

“Finally, the issue was settled by a three-judge bench in Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal (2020) 7 SCC 1, wherein the bench overruling Navjot Sandhu (supra) and Shafhi Mohd. (supra) upheld the ratio in Anvar PV (supra) and held issuance of certificate under section 65-B(4) is a condition precedent for admissibility of computer-generated secondary evidence. It cannot be supplemented through oral evidence.”

The judge then applies that principle directly to the case, stating:

“Before admitting the electronic evidence, the certificate under Section 65B(4) is necessary, essential and mandatory.”

And:

“If it is a primary document, it has to be produced along with the hash value and if it is a secondary evidence, it can be admitted only if the certificate under Section 65B(4) of the 'Evidence Act' or now, Section 63(4) of the 'BSA' is produced and proved.”

The operative holding is even more directly phrased:

“Therefore, in absence of the certificate under Section 65B(4) of the 'Evidence Act' or Section 63(4) of the 'BSA', the Court cannot take decision in regards to admissibility of electronic evidence, the tape record in the present case.”

Verbatim quote containing "patent illegality":

“In exposition of above legal situation, in the considered opinion of this Court, the impugned order passed by the trial Court, ignoring the aforesaid provision having the value of a binding precedent, dehors the same and is a patent illegality, and therefore, without entering further merits of the case, the impugned order is required to be set aside and the application is required to be remanded back to the learned trial Court to decide the same afresh, after following the aforesaid binding precedent.”

Does the fact pattern match (oral bungalow sale agreement, audio recording of a phone call, FSL referral)? Quote the line that shows it.
Yes. It matches essentially point-for-point.

The judgment states:

“The brief facts of the case are that, the respondents - original plaintiffs have instituted a Special Civil Suit No.187 of 2016 against the petitioners - defendants claiming, specific performance of oral agreement alleged to have been entered into with the petitioners for the sale of the immovable property consisting of bungalow situated in Muni Hemchandra Acharya Co-operative Housing Society, known as 'Bhikhubhai Bungalows'.”

It then states:

“The respondents - plaintiffs claim that they recorded the talks between the parties, which establish that the concluded contract was executed.”

And specifically:

“What could be inferred from the impugned order that the plaintiffs have filed a suit for specific performance alleging that the oral agreement executed between the parties and the plaintiffs have recorded the telephonic conversation alleged to have taken place between the plaintiff and defendant, constituting concluded contract.”

The FSL referral is explicit. The trial court ordered:

“It is ordered that the audio tape submitted in the current suit shall be sealed in the presence of the Registrar and sent through a Special Bailiff to the F.S.L. (Forensic Science Laboratory), Gandhinagar for examination.”

It further ordered the FSL to examine the tape for tampering and, if necessary, obtain the parties' voice samples.

The High Court ultimately allowed the petition, quashed and set aside the trial court's order, and remanded the FSL-related application for fresh decision in accordance with the governing electronic-evidence law.

One important precision for your police-facing document: the exact judgment does not use the phrase “sending to FSL before deciding admissibility is a patent illegality” verbatim. The judgment first holds that the certificate requirement controls admissibility and says the court cannot decide admissibility in its absence; it then characterizes the impugned trial-court order, which proceeded with the FSL route, as a “patent illegality.”

The Gujarat High Court's official website was reachable, and it currently lists Hon'ble Mr. Justice J.C. Doshi as a serving judge.

Confidence: 100/100. What would change my mind would be discovery of an official court record contradicting the Indian Kanoon judgment or showing that the document is not an authentic Gujarat High Court judgment. The identifying details here are independently consistent: case number, date, judge, oral bungalow-sale facts, telephonic recording, FSL order, Section 65B/63(4) analysis, and the “patent illegality” conclusion all occur in the opened judgment itself.
