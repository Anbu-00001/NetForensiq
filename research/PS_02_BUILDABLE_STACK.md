# PS-02 — The Buildable Stack: Open Models, Datasets & APIs for a 36-Hour Demo

> Research doc for KANAD S.H.I.E.L.D. 2026 (Cyber Crime Branch, Ahmedabad City Police).
> Scope: **concrete, nameable, installable-today components** — not architecture advice.
> Every row below is something you can `pip install`, `git clone`, or sign up for this week.
> PS references use the short codes defined in the table below (see
> `PS_00_OFFICIAL_PROBLEM_STATEMENTS.md` for full text).

**PS short codes used throughout:**

| Code | Problem statement | Code | Problem statement |
|---|---|---|---|
| C1‑PS1 | Big Data Analysis Tool | C2‑PS1 | Cyber-Integrated Safety Platform for Women |
| C1‑PS2 | DARKTRACE (dark web) | C2‑PS2 | Cyber Safety Platform for Children |
| C1‑PS3 | Mule Bank Account Detection | C2‑PS3 | Safety/Welfare Platform for Senior Citizens |
| C1‑PS4 | IntelliBank | C2‑PS4 | Unified Legal & Government Intelligence Platform |
| C1‑PS5 | CryptoTrack | C2‑PS5 | Health & Wellness Monitoring for Police Personnel |
| C1‑PS6 | SMIntelliTrack (social media OSINT) | C2‑PS6 | CrimeGPT (crime documentation automation) |
| C1‑PS7 | CallGuard (spoof/spam/VoIP calls) | C2‑PS7 | Crime Hotspot Mapping & Predictive Patrol |
| C1‑PS8 | TruthShield (deepfake/fake news) | C2‑PS8 | Network & Packet Forensics Platform |
| C1‑PS9 | TeleScan AI (Telegram monitoring) | C2‑PS9 | Real-Time Data Breach Alert System |
| C1‑PS10 | Mobile Hygiene Guardian | C2‑PS10 | Open-Ended Innovation Platform |
| C1‑PS11 | ForensiX (mobile forensics) | | |
| C1‑PS12 | VisionScan (CCTV analysis) | | |
| C1‑PS13 | VoiceInsight (call transcription) | | |
| C1‑PS14 | SIMScanner | | |
| C1‑PS15 | CellScope | | |
| C1‑PS16 | SafeInbox (email threat detection) | | |

**Reading key:** Maturity = 🟢 production-grade / actively maintained · 🟡 usable but rough edges or
research-grade · 🔴 fragile, unmaintained, or access-gated. GPU column: **CPU** = fine on a laptop,
**GPU-lite** = works on a free-tier Colab T4 / 6GB laptop GPU, **GPU** = wants a real card (8GB+).
⚠️ UNVERIFIED marks anything I could not confirm against a primary source in this session.

---

## Master table

| Capability | Tool / Model | Licence | CPU/GPU | Maturity | Serves |
|---|---|---|---|---|---|
| Hindi/English ASR (general) | OpenAI Whisper (large-v3, turbo) | MIT (code); weights open | GPU (CPU workable, slow) | 🟢 | C1‑PS13, C1‑PS7, C2‑PS6 |
| Fast Whisper inference | faster-whisper (CTranslate2) | MIT | CPU or GPU-lite | 🟢 | C1‑PS13, C2‑PS6 |
| Multilingual Indic ASR (22 langs incl. Gujarati) | AI4Bharat IndicConformer-600M-multilingual | MIT | GPU-lite (600M params) | 🟡 | C1‑PS13, C1‑PS9, C1‑PS2 |
| Hindi-specific ASR fine-tune | AI4Bharat IndicWhisper (Whisper fine-tunes on Vistaar) | MIT/CC (check per checkpoint) | GPU-lite | 🟡 | C1‑PS13 |
| Indic MT (22 languages) | AI4Bharat IndicTrans2 (1B base / 200-320M distilled) | MIT (checkpoints) | CPU (distilled) / GPU (base) | 🟢 | C1‑PS2, C1‑PS9, C1‑PS6, C2‑PS4 |
| Indic encoder / classification | IndicBERT v3 (270M/1B/4B) | MIT-family (verify per card) | CPU (270M) / GPU (4B) | 🟡 | C1‑PS8, C1‑PS6, C2‑PS9 |
| Hindi instruction-tuned LLM | AI4Bharat Airavata (7B, OpenHathi/Llama2 base) | Llama 2 community licence (research/eval note) | GPU | 🟡 | C2‑PS6, C2‑PS4 |
| Speaker diarisation | pyannote.audio 3.1 pipeline | MIT (gated HF access) | CPU default, GPU optional | 🟢 | C1‑PS13, C2‑PS6 |
| Official government MT/ASR/TTS/OCR APIs | Bhashini / ULCA APIs | Free (govt), quota unclear | Cloud API | 🟡 | C1‑PS13, C1‑PS2, C2‑PS1‑3 |
| Gujarati OCR (baseline) | Tesseract `guj.traineddata` | Apache-2.0 | CPU | 🟡 (high CER ~18%) | C1‑PS1, C2‑PS4, C2‑PS6 |
| Gujarati/Indic OCR (better) | PaddleOCR (multilingual) | Apache-2.0 | CPU/GPU-lite | 🟢 (CER ~4.5% vs Tesseract 18%, English-language benchmark; verify on Gujarati) | C1‑PS1, C2‑PS4 |
| Layout-aware OCR | Surya OCR | GPL-3.0 (⚠️ copyleft — flag for procurement) | GPU-lite | 🟡 | C2‑PS4, C1‑PS1 |
| Deepfake video/image detector benchmark+weights | DeepfakeBench (36 methods, incl. Xception/EfficientNet/F3Net) | CC BY-NC-4.0 (non-commercial) | GPU | 🟡 | C1‑PS8 |
| Deepfake image classic baseline | MesoNet / MesoInception (in DeepfakeBench) | Research (paper code, mostly MIT-ish reimpls) | CPU/GPU-lite | 🟡 | C1‑PS8 |
| Audio spoof/deepfake detection | AASIST (clovaai) | Apache-2.0/MIT-style (check repo) — AASIST3 variant is CC BY-NC-ND | GPU-lite | 🟡 | C1‑PS7, C1‑PS8 |
| Audio spoof detection alt | RawNet2 / RawGAT-ST | Research licence (academic) | GPU-lite | 🟡 | C1‑PS7, C1‑PS8 |
| Deepfake training/eval data | FaceForensics++ | Research-only, ToS agreement required | — (dataset) | 🟡 access-gated | C1‑PS8 |
| Deepfake training/eval data | Celeb-DF v2 | Research-only, request form | — | 🟡 access-gated | C1‑PS8 |
| Deepfake training/eval data | DFDC (Facebook) | Research-only, Kaggle terms | — | 🟡 access-gated | C1‑PS8 |
| Content provenance standard | C2PA / Content Credentials | Open standard, royalty-free spec | — | 🟢 spec / 🟡 real coverage | C1‑PS8 |
| AI-image watermark (closed) | Google SynthID | Proprietary, detector not public | — | 🔴 for a hackathon build | C1‑PS8 |
| Object detection (general) | Ultralytics YOLOv8 / YOLO11 | AGPL-3.0 (or paid commercial licence) | CPU (slow) / GPU | 🟢 | C1‑PS12, C1‑PS1 |
| Object detection (permissive) | RT-DETR (Baidu, in Ultralytics & PaddleDetection) | Apache-2.0 (PaddleDetection) | GPU | 🟢 | C1‑PS12 |
| Multi-object tracking | ByteTrack | MIT | CPU/GPU-lite | 🟢 | C1‑PS12 |
| Multi-object tracking (appearance) | BoT-SORT | MIT | GPU-lite | 🟢 | C1‑PS12 |
| Person re-identification | torchreid / FastReID | MIT/Apache-2.0 | GPU | 🟡 | C1‑PS12 |
| Face recognition (code) | InsightFace (library) | MIT (code) | GPU-lite | 🟢 | C1‑PS12 (⚠️ legal caution below) |
| Face recognition (weights) | InsightFace buffalo_l / ArcFace weights | **Non-commercial research only** | GPU-lite | 🟡 access-restricted | C1‑PS12 |
| Face recognition (alt) | DeepFace (wraps VGG-Face/ArcFace/Facenet) | MIT (wrapper); underlying weights vary | CPU/GPU-lite | 🟢 | C1‑PS12 |
| Indian ANPR dataset | DataCluster Labs Indian Number Plates | **CC BY-NC-ND 4.0** (sample set) | — | 🟡 | C1‑PS12 |
| Indian ANPR dataset/model | Indian_LPR (sanchit2843) | Check repo (mostly MIT-style research code) | GPU-lite | 🟡 | C1‑PS12 |
| Natural-language video/image search | OpenCLIP + FAISS | MIT (OpenCLIP) / MIT (FAISS) | CPU (small) / GPU (batch) | 🟢 | C1‑PS12 |
| Small video-understanding LLM | LLaVA-NeXT-Video-7B | Apache-2.0 / Llama-2 license mix (check base) | GPU (7B) | 🟡 | C1‑PS12, C2‑PS6 |
| Graph library (in-process) | NetworkX | BSD-3 | CPU | 🟢 | C1‑PS3, C1‑PS4, C1‑PS5 |
| Graph library (fast, C++) | igraph (python-igraph) | GPL-2.0 | CPU | 🟢 | C1‑PS3, C1‑PS4, C1‑PS5 |
| Graph database | Neo4j Community Edition | GPLv3 | CPU | 🟢 | C1‑PS3, C1‑PS4, C1‑PS2, C1‑PS5 |
| Graph database (alt, fast) | Memgraph (Community) | BSL 1.1 (⚠️ not OSI-approved — converts to Apache-2 after 4 yrs; check current terms) | CPU/GPU-lite | 🟡 | C1‑PS3, C1‑PS4 |
| GNN for fraud detection | PyTorch Geometric (PyG) | MIT | GPU | 🟢 | C1‑PS3, C1‑PS4, C1‑PS5 |
| GNN for fraud detection (alt) | DGL (Deep Graph Library) | Apache-2.0 | GPU | 🟢 | C1‑PS3, C1‑PS4 |
| Record linkage / entity resolution | Splink (probabilistic, Fellegi-Sunter) | MIT | CPU | 🟢 | C1‑PS1, C1‑PS3, C1‑PS4 |
| Record linkage (classic) | dedupe (Python) | MIT | CPU | 🟡 (slower on very large data) | C1‑PS1, C1‑PS3 |
| Full-text/log search | Elasticsearch (Basic, self-hosted) | SSPL / Elastic License 2.0 (⚠️ not OSI-approved since 2021) | CPU | 🟢 | C1‑PS1, C1‑PS2 |
| Full-text/log search (Apache-licensed fork) | OpenSearch | Apache-2.0 | CPU | 🟢 | C1‑PS1, C1‑PS2 |
| Fast local analytics on CSV/Parquet | DuckDB | MIT | CPU | 🟢 | C1‑PS1, C1‑PS3, C1‑PS4 |
| Fast local analytics (columnar OLAP) | ClickHouse | Apache-2.0 | CPU | 🟢 | C1‑PS1 |
| BI dashboards | Apache Superset | Apache-2.0 | CPU | 🟢 | C1‑PS1, C1‑PS3, C1‑PS4, C2‑PS7 |
| BI dashboards (simpler) | Metabase (OSS edition) | AGPL-3.0 | CPU | 🟢 | C1‑PS1, C1‑PS3 |
| Bitcoin block/tx explorer API | Blockstream Esplora (public + self-host) | MIT (Esplora code); public API free | Cloud API / self-host CPU | 🟢 | C1‑PS5 |
| Bitcoin mempool/fee/tx API | mempool.space API | AGPL-3.0 (self-host); public API free | Cloud API | 🟢 | C1‑PS5 |
| Ethereum/EVM explorer API | Etherscan API | Free tier: 5 req/s, 100k/day | Cloud API | 🟢 | C1‑PS5 |
| Multichain indexed API | Covalent / GoldRush | Free trial: 14 days, 25k credits, then paid from $10/mo | Cloud API | 🟡 (not perpetually free) | C1‑PS5 |
| Multichain GraphQL API | Bitquery | Free tier exists; limits ⚠️ UNVERIFIED (check current docs) | Cloud API | 🟡 | C1‑PS5 |
| Open-source blockchain analytics platform | GraphSense (Iknaio) | MIT (core), Apache-2.0 components | Self-host, heavy (Cassandra/Spark) | 🟡 (setup-heavy for 36h) | C1‑PS5 |
| Labelled illicit/licit Bitcoin tx dataset | Elliptic / Elliptic++ dataset | Free via Kaggle; licence terms on Kaggle page (check before redistribution) | CPU (graph is small: 203k tx) | 🟢 | C1‑PS5 |
| Sanctioned crypto addresses | OFAC SDN list (crypto addresses) | US Government public data; community CSV/XML parsers on GitHub | CPU | 🟢 | C1‑PS5 |
| OSINT automation framework | SpiderFoot (OSS edition) | MIT | CPU | 🟢 | C1‑PS6, C1‑PS2 |
| OSINT link-analysis GUI | Maltego (Basic/Community) | Free "Basic" tier: 200 credits/mo, up to 24 results/transform, 10k entities/graph | CPU (client) + cloud transforms | 🟡 (was CE, now "Basic") | C1‑PS2, C1‑PS6, C1‑PS3 |
| Email/domain harvesting | theHarvester | GPL-3.0 (approx.; check repo) | CPU | 🟢 | C1‑PS6, C1‑PS16 |
| Username enumeration across platforms | Sherlock | MIT | CPU | 🟢 | C1‑PS6, C1‑PS9 |
| Email-to-account-existence OSINT | Holehe | MIT | CPU | 🟢 | C1‑PS6, C1‑PS16 |
| Tor access / .onion crawling | Tor + `stem` (Python controller) | BSD (stem) / Tor: BSD-3 | CPU | 🟢 (⚠️ legal/ethics gate — see Traps) | C1‑PS2 |
| Dark-web search index (surface entry point) | Ahmia | AGPL-3.0 (Ahmia codebase) | — (use as index, don't re-crawl blind) | 🟡 | C1‑PS2 |
| Telegram scraping (userbot) | Telethon (MTProto) | MIT | CPU | 🟢 (⚠️ ToS/rate-limit/ban risk) | C1‑PS9 |
| Telegram scraping (official lib) | TDLib | Boost Software License 1.0 | CPU | 🟢 | C1‑PS9 |
| Reddit as X-alternative source | Reddit API (OAuth) | Free tier: 100 QPM; commercial tier $12k/mo+ | Cloud API | 🟡 (free tier is workable for a demo) | C1‑PS6, C1‑PS2 |
| X/Twitter data (2026 reality) | X API | Free tier discontinued Feb 2026; now pay-per-use ($0.005/read, capped 2M reads/mo) | Cloud API | 🔴 (budget risk — avoid live pulls in demo) | C1‑PS6 |
| Fediverse alternative | Mastodon API / Bluesky (AT Protocol) API | Open, free, no paid tier | Cloud API | 🟢 | C1‑PS6 |
| Network traffic analysis (protocol-aware) | Zeek | BSD-3 | CPU | 🟢 | C2‑PS8 |
| IDS/IPS signatures | Suricata | GPLv2 | CPU | 🟢 | C2‑PS8 |
| PCAP full-session viewer | Arkime (formerly Moloch) | Apache-2.0 | CPU (Elasticsearch backend) | 🟢 | C2‑PS8 |
| Packet crafting/parsing | Scapy | GPLv2 | CPU | 🟢 | C2‑PS8 |
| CLI packet inspection | tshark (Wireshark) | GPLv2 | CPU | 🟢 | C2‑PS8 |
| Sample PCAPs (malware C2) | malware-traffic-analysis.net | Free download, site's own terms (educational use) | — | 🟢 | C2‑PS8 |
| Labelled IDS dataset | CIC-IDS2017 (UNB) | Free for research, registration/ToS on site | — | 🟢 | C2‑PS8 |
| Labelled IDS/CTF pcaps | MACCDC pcaps (via Netresec) | Free download | — | 🟢 | C2‑PS8 |
| Disk/file forensics suite | Autopsy + The Sleuth Kit | Apache-2.0 (Autopsy) / IPL-1.0 (Sleuth Kit — verify) | CPU | 🟢 | C1‑PS11, C2‑PS8 |
| Android artifact parser | ALEAPP | MIT-style OSS (verify per-repo LICENSE) | CPU | 🟢 | C1‑PS11 |
| iOS artifact parser | iLEAPP | MIT-style OSS (verify per-repo LICENSE) | CPU | 🟢 | C1‑PS11 |
| WhatsApp crypt14 decryption | `whatsapp-crypt14-15-decrypt` / wa-crypt-tools | Open-source (community, check repo) | CPU | 🟡 (needs key or KeyStore access — see Traps) | C1‑PS11 |
| EML/MSG parsing | Python `eml_parser`, `extract-msg` | MIT/Apache-2.0 | CPU | 🟢 | C1‑PS16 |
| SPF/DKIM/DMARC verification | `checkdmarc`, `pyspf`, `dkimpy`, `parsedmarc` | Apache-2.0 / BSD | CPU | 🟢 | C1‑PS16 |
| URL/file threat intel | VirusTotal Public API | Free: 500 req/day, 4 req/min | Cloud API | 🟢 | C1‑PS16, C1‑PS2 |
| URL scanning/screenshot | urlscan.io | Free tier with per-account quotas (exact numbers vary; check `/user/quotas`) | Cloud API | 🟢 | C1‑PS16 |
| Phishing URL feeds | PhishTank / OpenPhish (community feed) | Free (attribution required) | — | 🟢 | C1‑PS16 |
| Web maps | Leaflet / MapLibre GL JS | BSD-2 / BSD-3 | CPU (browser) | 🟢 | C2‑PS7, C1‑PS15, C1‑PS14 |
| Basemap + geocoding data | OpenStreetMap + Overpass API | ODbL | Cloud API / self-host | 🟢 | C2‑PS7 |
| Hotspot clustering | scikit-learn DBSCAN, HDBSCAN | BSD-3 | CPU | 🟢 | C2‑PS7 |
| Spatial statistics (KDE, LISA) | PySAL | BSD-3 | CPU | 🟢 | C2‑PS7 |
| Hex spatial indexing | H3 (Uber) | Apache-2.0 | CPU | 🟢 | C2‑PS7 |
| Routing engine (patrol routes) | OSRM | BSD-2 | CPU | 🟢 | C2‑PS7 |
| Routing engine (alt) | Valhalla | MIT | CPU | 🟢 | C2‑PS7 |
| Routing engine (hosted) | OpenRouteService | GPLv3 (self-host) / free API quota (hosted) | Cloud API or self-host | 🟢 | C2‑PS7 |
| Cell tower geolocation DB | OpenCelliD | CC BY-SA 4.0, free API key, full DB export | Cloud API / CSV | 🟢 (data window ~18 months) | C1‑PS15, C1‑PS14 |
| Indian crime statistics | NCRB "Crime in India" via data.gov.in / dataful.in | Government Open Data Licence – India | — | 🟡 (district-year aggregates, not incident-level) | C2‑PS7 |
| Local LLM runtime | Ollama | MIT | CPU/GPU-lite | 🟢 | C2‑PS6, C2‑PS4, C2‑PS10 |
| Local LLM runtime (low-level) | llama.cpp | MIT | CPU/GPU-lite | 🟢 | all LLM PS |
| Local LLM serving (throughput) | vLLM | Apache-2.0 | GPU | 🟢 | C2‑PS6, C2‑PS4 |
| RAG orchestration | LlamaIndex | MIT | CPU | 🟢 | C2‑PS6, C2‑PS4 |
| RAG orchestration (alt) | LangChain | MIT | CPU | 🟢 | C2‑PS6, C2‑PS4 |
| Vector DB (embedded) | ChromaDB | Apache-2.0 | CPU | 🟢 | C2‑PS6, C2‑PS4 |
| Vector DB (server) | Qdrant | Apache-2.0 | CPU/GPU-lite | 🟢 | C2‑PS6, C2‑PS4 |
| Vector search (library) | FAISS (Meta) | MIT | CPU/GPU | 🟢 | C1‑PS12, C2‑PS6 |
| Indian legal judgment corpus/API | Indian Kanoon API | Free tier via registration; **"Powered by IKanoon" attribution mandatory**, "AS IS" no warranty | Cloud API | 🟡 | C2‑PS4, C2‑PS6 |
| Indian legal NLP toolkit | OpenNyAI (Legal NER, rhetorical-role structuring) | Open-source (EkStep, check licence per repo) | CPU/GPU-lite | 🟡 | C2‑PS4, C2‑PS6 |
| Judicial case data | National Judicial Data Grid (NJDG) | Public dashboard; bulk API access unclear ⚠️ UNVERIFIED | Cloud (portal) | 🟡 | C2‑PS4 |
| Hindi instruction LLM (base for legal) | OpenHathi (Llama-2 extension) / Airavata | Llama 2 community licence | GPU | 🟡 | C2‑PS4, C2‑PS6 |
| Synthetic data generation | Faker (incl. `faker` locale support, community Indian-name providers) | MIT | CPU | 🟢 | all PS (demo data) |
| Containerisation | Docker / Docker Compose | Apache-2.0 (Engine) | CPU | 🟢 | all PS (deliverable requirement) |

---

## 1. Indian-language speech & NLP (VoiceInsight, CrimeGPT, citizen platforms)

**Core recommendation: AI4Bharat's IndicConformer for Indic ASR, faster-whisper for English/Hindi, IndicTrans2 for translation, pyannote for diarisation.**

- **AI4Bharat IndicConformer-600M-multilingual** (`ai4bharat/indic-conformer-600m-multilingual`, HuggingFace) — MIT licence, 600M params, covers all 22 scheduled Indian languages including Gujarati (`gu`), loads via `AutoModel.from_pretrained()` (transformers + torchaudio). This is the most directly relevant model for VoiceInsight/C1‑PS13 and TeleScan/C1‑PS9 since it's purpose-built for Indian languages rather than fine-tuned from an English-first model.
- **IndicWhisper** — AI4Bharat's Whisper fine-tunes trained on the **Vistaar** benchmark/training set (`AI4Bharat/vistaar` on GitHub); IndicWhisper models achieve the lowest WER on 39 of 59 Vistaar benchmark splits, beating other public models on Indian-language ASR. Good fallback if IndicConformer underperforms on your specific audio domain (phone-call quality, background noise).
- **Honesty on Gujarati accuracy:** a cross-model comparison referenced in the Vistaar/IndicContextEval line of work put Gujarati WER (at a "prompt level 5" difficulty) at roughly: Sarvam 11.4%, Gemini-class ~12%, GPT-4o-class ~31%, and a small open model (Gemma-3N) at ~57%. **Take-away: expect double-digit WER on real Gujarati call recordings even with the best models, and expect code-mixed Gujarati-Hindi-English to be materially worse than any single-language benchmark number** — none of the public benchmarks isolate code-switching, so budget review/correction time in any transcript pipeline you demo.
- **OpenAI Whisper + faster-whisper** — Whisper is MIT-licensed (code; weights openly released by OpenAI). faster-whisper (CTranslate2 backend, MIT) is **up to 4x faster with less memory** than the reference implementation, confirmed on its own benchmark table (large-v2: 1m03s vs 2m23s on GPU for 13 min of audio; int8 quantization drops memory ~40%). This is your practical choice for **CPU-only laptop demos** — the `distil-large-v3` and `turbo` checkpoints are the sweet spot for a hackathon machine.
- **IndicTrans2** (`AI4Bharat/IndicTrans2`, GitHub) — MIT-licensed checkpoints, covers all 22 scheduled languages across Devanagari/Perso-Arabic/Ol Chiki/Meitei/Latin scripts. Ships **two size tiers**: 1B "base" models (need GPU) and **200–320M distilled models** (run fine on CPU) — use the distilled tier for a live demo, the base tier if you have a GPU and want quality for a written report.
- **IndicBERT-v3** (270M / 1B / 4B parameter tiers on HuggingFace) — use the 270M tier for CPU-viable classification/NER (keyword tagging, entity extraction from transcripts) in C1‑PS13/C2‑PS6.
- **Airavata** (AI4Bharat, 7B, Hindi instruction-tuned, fine-tuned from **OpenHathi**, which extends Llama-2) — good base for a Hindi-first chat assistant, but it inherits the **Llama 2 Community Licence** (not a permissive OSS licence — has a 700M-MAU commercial-use clause and requires the Llama attribution notice). Fine for a hackathon demo; flag it explicitly if this goes to procurement.
- **Bhashini / ULCA APIs** (`bhashini.gov.in`) — the official Government of India multilingual API layer (ASR/MT/TTS/OCR pipeline). **How to get a key:** register at `bhashini.gov.in/ulca/user/register`, verify email, log in, go to "My Profile" → Generate, name the app in lowercase+underscores. **One account can create up to 5 keys.** You need both the **User ID** and the **API key** together for pipeline calls. ⚠️ UNVERIFIED: exact rate limits and whether the service is unconditionally free at scale — the public docs describe the key-creation flow but not a published quota; treat it as a "get it running Day 1, don't depend on it for live-demo-day throughput" resource, and have a local (IndicConformer/faster-whisper) fallback ready in case the venue wifi or the API rate-limits you mid-demo.
- **pyannote.audio 3.1** (`pyannote/speaker-diarization-3.1`, HuggingFace) — MIT-licensed pipeline, but **gated**: you must accept a click-through agreement on the model card (they collect contact info, may email about paid tiers) and get an HF access token. Runs on **CPU by default**; can be moved to GPU with one line of PyTorch. Requires mono 16kHz audio (auto-converted). This is the direct tool for the "speaker diarisation (who said what)" bonus feature explicitly named in C1‑PS13.
- **Gujarati OCR:** Tesseract's `guj.traineddata` (Apache-2.0, part of `tesseract-ocr/tessdata`) is the zero-setup baseline but is weak on Indic scripts because Tesseract's default segmentation logic doesn't natively handle dependent vowel signs that appear *before* their consonant in Gujarati/Devanagari — a documented, structural limitation, not a training-data problem. A comparative study found **PaddleOCR at 4.5% CER / 92.1% word accuracy vs. Tesseract's 18.2% CER / 75.8%** on Gujarati text images — treat PaddleOCR (Apache-2.0) as the default over Tesseract for anything beyond a quick demo. **Surya OCR** is a strong general Indic-script layout-aware OCR (benchmarked around 8.8% CER on Sinhala, a similarly-structured script, giving a rough proxy for Gujarati difficulty) but ships under **GPL-3.0** — a copyleft licence that matters if this tool is meant to feed a police procurement pathway with a non-GPL codebase.
- **Transliteration:** AI4Bharat also publishes transliteration models/tools under the same IndicXlit family (check `ai4bharat/indicxlit` on GitHub) — useful for normalising Gujarati-script vs. Roman-script ("Gujlish") chat/SMS text before running NLP.

## 2. Deepfake / synthetic media detection (TruthShield)

**Be blunt with the judges about this category: no open detector generalises reliably to unseen, real-world content. Build the demo to look convincing on curated examples, and say so explicitly rather than over-claiming.**

- **DeepfakeBench** (`SCLBD/DeepfakeBench`, GitHub) — the best starting point: a **NeurIPS 2023** unified benchmark shipping **36 pretrained detector implementations** with weights, spanning naive detectors (Xception, MesoNet, MesoInception, EfficientNet-B4), spatial detectors (Face X-ray, CORE, RECCE, UCF, SBI, LSDA, Effort, etc.), frequency-domain detectors (F3Net, SPSL, SRM), and video detectors (I3D, TALL, FTCN, VideoMAE, X-CLIP). **Licence: CC BY-NC-4.0 — non-commercial only**, which is fine for a hackathon demo but is a hard blocker for a direct-to-procurement path without re-licensing/re-training. GPU strongly recommended (Docker image assumes `--gpus all`).
- **Audio deepfake/spoof detection:** **AASIST** (`clovaai/aasist`, NAVER, official PyTorch implementation) trained/evaluated on **ASVspoof 2019 LA**, ships pretrained weights, and is one of the most widely cited open spoof detectors — it fuses raw-waveform convolution with graph-attention over spectro-temporal features. **RawNet2** training is also supported inside the same repo. The newer **AASIST3** variant on HuggingFace is explicitly **CC BY-NC-ND 4.0** (non-commercial, no derivatives) — check the licence on whichever checkpoint you actually pull, they differ. This is directly usable for the acoustic side of C1‑PS7 (spoofed/VoIP call detection) as well as C1‑PS8.
- **Face/video datasets — access terms matter for a police pathway:**
  - **FaceForensics++** — 1,000 real + 4,000 manipulated videos (DeepFakes/Face2Face/FaceSwap/NeuralTextures); **research-only, requires signing/submitting a ToS request form** to the Technical University of Munich team before download.
  - **Celeb-DF v2** — 590 real + 5,639 fake videos; **research-only, request-form gated** (`github.com/yuezunli/celeb-deepfakeforensics`).
  - **DFDC** (Facebook/Meta) — 128,154 videos, largest public face-swap set; distributed via Kaggle under **research-only competition terms**.
  - None of these three are redistributable or usable for a commercial product without separate licensing — fine for training/demo, a real blocker to mention in your submission if procurement is the end goal.
- **Cross-dataset generalisation — the number to put in your slide deck:** models trained on FaceForensics++ average **AUC 0.905 on DeeperForensics-1.0 but only 0.633 on Celeb-DF** (same task, different generator) — a >25-point AUC collapse from a distribution shift alone. Independent field evaluation (**DeepFake-Eval-2024**) found leading **commercial** detectors achieve only **~78% accuracy on in-the-wild deepfakes**, and some open SOTA detectors show **AUC drops of 45–50%** on real-world content vs. their lab benchmark numbers. Transformer-based detectors generalise somewhat better than CNN-based ones (~11% vs. >15% average performance decline cross-dataset), but "somewhat better" is not "solved." **Recommendation for the demo: show a live inference on a handful of known/curated fake+real clips, report a trust score with visible uncertainty, and explicitly state the generalisation caveat in the pitch** — judges with any ML background will respect the honesty and penalise an unqualified "99% accurate" claim.
- **Image manipulation (classic forensics, no training needed):** Error Level Analysis (ELA) is a few lines of PIL/OpenCV (re-save at known JPEG quality, diff), good for a cheap illustrative signal but easily defeated and high false-positive on legitimately re-compressed/re-shared social images. PRNU sensor-noise fingerprinting needs a reference camera fingerprint database you almost certainly won't have in 36 hours — mention it as "future work," don't try to build it live.
- **Provenance instead of detection:** **C2PA / Content Credentials** is an open, royalty-free standard (backed by a 6,000+ member coalition including Google, Microsoft, Adobe, OpenAI, Sony, BBC) for cryptographically signing media at capture/edit time — as of 2026 it's shipping in Pixel 10 (top conformance tier) and Galaxy S25 camera pipelines, and Microsoft 365. **Google SynthID** has watermarked 100B+ images/video/audio files, but **the watermark pattern and detector are proprietary/closed** — you cannot build a SynthID *detector* yourself, only rely on Google's own verification tools where they exist. Both approaches only work for content that was watermarked/signed at creation — **neither helps you detect a deepfake made with a tool that doesn't participate**, which as of 2026 is still the majority of accessible generation tools. This is a legitimate, honest "future direction" slide, not a buildable Day-1 component.
- **Reverse image search:** no free, generous API exists for this anymore (Google/Bing/TinEye reverse image search are all paid or heavily rate-limited for API use) — for a demo, either use a curated local FAISS+CLIP index (see Video/CCTV section) over a small demo corpus, or manually screenshot browser-based reverse search as an illustrative (non-automated) step.

## 3. Video/CCTV analytics (VisionScan)

- **Object detection:** **Ultralytics YOLOv8/YOLO11** is the fastest path to a working demo — but note it ships under **AGPL-3.0** (or Ultralytics' paid commercial licence for closed-source use); for a hackathon this is a non-issue, but flag it for procurement. If you want a fully permissive alternative, **RT-DETR** (Baidu; available via PaddleDetection under **Apache-2.0**, and also wrapped inside Ultralytics) gives transformer-based detection without the AGPL constraint on the reference implementation.
- **Tracking:** **ByteTrack** and **BoT-SORT** (both MIT) are the standard multi-object trackers to pair with YOLO output for "track a person/vehicle across frames" — ByteTrack is simpler/faster, BoT-SORT adds appearance (re-ID) matching for better ID-switch robustness in crowded CCTV scenes.
- **Person re-identification:** **torchreid** and **FastReID** (MIT/Apache-2.0) — needed if VisionScan's "search by reference image" requirement (re-identify a person across multiple, non-overlapping camera feeds) is taken seriously; both need GPU and non-trivial fine-tuning data to work well on Indian CCTV footage quality (low-res, oblique angles, poor lighting) — treat as a stretch goal, demo with best-case footage.
- **Face recognition — code vs. weights split matters:** **InsightFace**'s *code* is MIT (unrestricted), but its high-accuracy pretrained weights (**buffalo_l**, ArcFace-based) are **explicitly non-commercial-research-only**, with a separate commercial licensing contact required for production use. **DeepFace** (MIT wrapper around VGG-Face/Facenet/ArcFace/etc.) is the friendlier drop-in library if you want to avoid manually tracking per-model licence terms, though the underlying weights it pulls in inherit the same restrictions. **Legal caution, stated explicitly for the pitch deck:** face recognition against a real crowd/CCTV feed in India sits inside Puttaswamy-derived privacy jurisprudence and (once notified) the DPDP Act 2023's consent/processing rules — a hackathon demo should use **only consenting/staged subjects or public-domain faces**, never live footage of bystanders, and the pitch should proactively name the legal-basis and audit-trail requirements a production VisionScan would need (purpose limitation, retention limits, human-in-the-loop review) rather than presenting face-match as a fire-and-forget automated identification.
- **ANPR (Indian plates):** no single "official" open Indian ANPR dataset exists. Options: **DataCluster Labs' Indian Number Plates dataset** (HuggingFace/Roboflow) is useful but its sample release is **CC BY-NC-ND 4.0** (non-commercial, no derivatives — usable for eval, not for redistribution or a trained-model-as-product); the larger commercial dataset is paid. `sanchit2843/Indian_LPR` on GitHub (16,192 images / 21,683 plates, with a benchmark model) is a smaller fully-open alternative — quality and coverage is real but modest, and **models trained on non-Indian plates (US/China/Brazil datasets) reliably fail on Indian plate fonts/formats**, so don't substitute a generic ANPR model and claim India-readiness.
- **Natural-language video search:** **OpenCLIP (MIT) + FAISS (MIT)** is the correct, well-trodden combo for "search CCTV frames by keyword like 'red car' or 'man in black jacket'" — extract CLIP embeddings per sampled frame, index in FAISS, do nearest-neighbour search against a text embedding of the query. Runs fine on CPU for a demo-scale video (thousands of frames); GPU only matters if you're indexing many hours of multi-camera footage live.
- **Video-LLM on a laptop:** **LLaVA-NeXT-Video-7B** (HuggingFace `llava-hf/LLaVA-NeXT-Video-7B-hf`) is a realistic "runs on a laptop" option — general guidance for 7B-class multimodal models is a mid-range GPU (e.g., RTX 3060 12GB) for reasonable speed, or a CPU-only laptop via `llama.cpp`-style quantisation at the cost of multi-second-to-a-minute per response. For a *live* demo, precompute/cache summaries rather than calling the video-LLM interactively on stage.
- **Frame dedup / long-footage summarisation:** no single named "the" tool — the practical recipe is: sample at low FPS (1 frame every 1–2s), compute CLIP embeddings, drop near-duplicate frames by cosine-similarity threshold, then run detection/tracking only on the reduced set. This alone is often the single biggest "smart" feature you can demo cheaply, since raw CCTV has enormous redundant-frame ratios.

## 4. Graph analytics & entity resolution (Mule accounts, IntelliBank, Big Data tool, CDR)

- **In-memory graph analysis:** **NetworkX** (BSD-3) is the default for anything under ~100k nodes — every mule-account/CDR "who's connected to whom" feature in C1‑PS3/C1‑PS4/C1‑PS1 can be prototyped in it directly, and it's explicitly named in the official "Suggested Tools" list for those two PS.
- **Faster graph at scale:** **python-igraph** (GPL-2.0) if NetworkX gets too slow for tens/hundreds of thousands of edges — same algorithms (community detection, centrality, shortest paths), C backend.
- **Graph database:** **Neo4j Community Edition** (GPLv3) is explicitly named as a suggested tool in three of the official PS texts (Big Data, Mule Accounts, IntelliBank, DARKTRACE) — it's the safest choice precisely because the judges will recognise it. **Memgraph Community** is a faster in-memory alternative but ships under **BSL 1.1**, a source-available (not OSI-approved) licence that converts to Apache-2.0 only after a multi-year delay — fine to use for a demo, worth a footnote if evaluated on "open source" strictly.
- **GNN-based fraud/anomaly detection:** **PyTorch Geometric (MIT)** or **DGL (Apache-2.0)** — both support GraphSAGE/GAT-style node classification for "is this account a mule" as a semi-supervised link/node classification problem over the transaction graph; this is your best answer to the bonus-point "graph-based anomaly detection" line explicitly called out in C1‑PS3.
- **Entity resolution / record linkage:** **Splink** (MIT, by the UK Ministry of Justice's data science team) implements probabilistic (Fellegi-Sunter) record linkage and scales to large record sets via a DuckDB/Spark backend — directly relevant to "link accounts across identifiers (phone, UPI ID, IP)" in IntelliBank (C1‑PS4) and cross-source identity resolution in the Big Data tool (C1‑PS1). **dedupe** (MIT) is the more traditional/active-learning alternative, fine for smaller record sets but noticeably slower at scale.
- **Search/indexing:** **Elasticsearch** is named explicitly in the official Big Data PS text, but note it moved off an OSI-approved licence in 2021 (now **SSPL/Elastic License 2.0**, not "open source" in the strict sense) — **OpenSearch** (Apache-2.0, the AWS-led fork) is a drop-in, fully-open alternative if licence purity matters for a procurement narrative.
- **Fast local analytics on big CSVs:** **DuckDB** (MIT) is the single highest-leverage addition for this whole category — an embedded, zero-ops OLAP engine that runs SQL directly over CSV/Parquet files at surprising speed, with no server to stand up. For the "petabyte-scale... real-time search" framing in C1‑PS1, DuckDB on a laptop is honestly the realistic 36-hour answer once you're past the marketing language — pair it with **ClickHouse** (Apache-2.0) only if you actually need a persistent multi-user server.
- **Dashboards:** **Apache Superset** (Apache-2.0) for a full-featured BI layer, **Metabase OSS** (AGPL-3.0) if you want something even faster to stand up with less configuration.

## 5. Crypto tracing (CryptoTrack)

- **Bitcoin block/tx explorer:** **Blockstream's Esplora** — MIT-licensed backend, and the public instance (`blockstream.info/api`) is free with no published hard rate limit for reasonable use; self-hostable if you need guaranteed uptime for a demo.
- **Bitcoin mempool/fee data:** **mempool.space API** — public API is free; the underlying project is AGPL-3.0 if you want to self-host.
- **Ethereum/EVM:** **Etherscan API** — confirmed free tier is **5 requests/second and 100,000 requests/day**, more than sufficient for a demo; paid tiers start at $199/mo for higher throughput, don't touch that for a hackathon.
- **Multichain indexed data:** **Covalent (rebranded GoldRush)** — free access is a **14-day trial with 25,000 credits**, not a perpetual free tier; paid plans start at $10/mo. Plan your data-gathering to happen once, early, and cache results locally rather than depending on live calls during judging.
- **Bitquery** — has a free tier by reputation but I could not confirm current exact limits in this session — ⚠️ UNVERIFIED, check `bitquery.io/pricing` directly before relying on it.
- **Open-source full analytics platform:** **GraphSense** (Iknaio/graphsense, MIT core) does address clustering + tagging + graph exploration properly, but its reference deployment needs Cassandra + Spark — **too heavy to stand up from scratch in a 36-hour hackathon**; better to borrow its *methodology* (common-input-ownership heuristic, change-address heuristics) and implement a lightweight version yourself over Esplora/Etherscan data in DuckDB+NetworkX.
- **Address clustering heuristics (implement yourself, well-documented, no library needed):**
  - **Common-input-ownership heuristic** — all inputs to a single Bitcoin transaction are (with high confidence) controlled by the same entity; this is the textbook basis for wallet clustering.
  - **Change-address detection** — heuristics like "the output with a novel/unused address is likely the change" or round-number-output-is-payment are standard, imperfect, and worth explicitly caveating in a demo (both heuristics are defeated by CoinJoin/mixer usage, which is exactly the adversarial case investigators care about).
- **Labelled ground-truth dataset:** **Elliptic / Elliptic++** — free via **Kaggle** (`ellipticco/elliptic-data-set`), 203,769 labelled Bitcoin transactions (licit/illicit) with 234,355 edges, small enough to load entirely in memory; the Elliptic++ extension (`git-disl/EllipticPlusPlus` on GitHub) adds 822k wallet-address-level data. This is the single best "train a real fraud classifier and show a real confusion matrix" option in this whole document — check the Kaggle page's specific terms before any redistribution, but it's freely downloadable for use.
- **Sanctions screening:** **OFAC's SDN list** publishes designated cryptocurrency addresses inside its standard SDN XML/CSV feed (`treasury.gov/ofac`); no dedicated crypto API exists from Treasury, but several actively-maintained community repos (`0xB10C/ofac-sanctioned-digital-currency-addresses`, `bhemen/OFAC-SDN-analysis`) already parse it into clean per-chain address lists you can `git clone` and diff against your traced wallets directly — an easy, real "wallet interacted with a sanctioned address" feature.

## 6. OSINT & dark web (DARKTRACE, SMIntelliTrack, TeleScan)

- **General OSINT automation:** **SpiderFoot** (MIT, open-source edition) automates username/domain/IP/email enumeration across 200+ modules — a strong base for actor-profiling features named in DARKTRACE (C1‑PS2).
- **Link-analysis GUI:** **Maltego** — the free tier is now called **"Basic"** (formerly "Community Edition"): **200 data credits/month**, up to **24 results per transform**, and (since Maltego Graph 4.8.0) **no limit on entities per graph** (older CE builds capped at 10,000) and commercial use is now permitted on Basic. Good for the visual "network graph of seller-buyer relations" requirement explicitly named in DARKTRACE, but the monthly credit cap means you should pre-run your queries before the live demo, not query live on stage.
- **theHarvester** (subdomain/email/employee OSINT), **Sherlock** (MIT, username-across-platforms enumeration — directly useful for the "track pseudonyms across platforms" requirement in DARKTRACE), and **Holehe** (MIT, checks which services an email is registered on) round out a classic OSINT toolkit — all CPU-only, all trivially scriptable.
- **Tor/.onion access:** **Tor** + the **`stem`** Python controller library (both BSD-licensed) let you script .onion access and build a basic crawler. **Ahmia** (AGPL-3.0) is a curated, already-crawled dark-web *search index* — use it as your entry-point/seed list rather than building a blind crawler from zero, which is both slower and more likely to hit CSAM/illegal content unintentionally.
  - **⚠️ Ethics/legality boundary, stated plainly:** dark-web crawling for this hackathon should be **read-only, keyword/metadata-level, and scoped to publicly-known indices (Ahmia, known forum listings)** — do not attempt to purchase, register, or interactively engage inside marketplaces, and do not build an unfiltered image/media crawler (CSAM exposure risk is real and a criminal-liability issue even for "research" crawling in most jurisdictions, India included). A defensible demo shows keyword-hit detection on **pre-captured, curated sample pages** (screenshots/HTML snapshots you control) rather than a live crawl of an actual live .onion marketplace in front of judges.
- **Telegram monitoring (TeleScan, C1‑PS9):** **Telethon** (MIT, MTProto-based userbot library) is the standard Python approach — scraping *public* channels/groups is broadly treated as no worse than reading a public forum, but Telegram **actively rate-limits and can ban accounts** that scrape aggressively, so build in backoff and expect account friction during a live demo; **TDLib** (Boost Software Licence 1.0, Telegram's own official client library) is the more robust/officially-sanctioned path for anything beyond a quick script, at the cost of more setup complexity. Both require a **real phone number + API ID/hash** from `my.telegram.org` — get this provisioned well before demo day, not during.
- **X/Twitter API — do not build around this in 2026.** As of February 2026, X **closed its free tier to new signups** and moved new developers to **pay-per-use pricing** (~$0.015/post created, $0.005/post read, capped at 2M reads/month); legacy flat tiers ($200/mo Basic, $5,000/mo Pro) still exist only for pre-existing subscribers. **Recommendation: don't demo live X data pulls at all** — either use a small pre-scraped/curated sample set (clearly labelled as such) or pivot the "X-alternative" framing explicitly to Reddit/Mastodon/Bluesky.
- **Reddit API** — free tier gives **100 queries/minute** (OAuth-authenticated) for public posts/comments/subreddit data — genuinely workable for a live SMIntelliTrack demo; the commercial tier ($12,000/mo for 50M calls, ~$0.24/1k calls beyond that) is irrelevant at hackathon scale.
- **Mastodon API and Bluesky's AT Protocol** — both fully open, no paid tier, straightforward REST/firehose access — good secondary/tertiary sources to diversify the "multi-platform" story in SMIntelliTrack (C1‑PS6) without touching X's new pricing.

## 7. Network & mobile forensics (Network & Packet Forensics, ForensiX)

- **Zeek** (BSD-3) for protocol-level network traffic analysis/logging, **Suricata** (GPLv2) for signature-based IDS/IPS alerting, **Arkime** (Apache-2.0, formerly Moloch) for full-session PCAP indexing/search with an Elasticsearch backend, **Scapy** (GPLv2) for scripted packet crafting/parsing, and **tshark** (GPLv2, Wireshark's CLI) for quick manual inspection — this five-tool stack covers essentially the full functional-requirements list of the Network & Packet Forensics Platform (C2‑PS8) with zero custom development needed for the ingestion/parsing layer; your actual build effort should go into the analyst-facing correlation/dashboard layer on top.
- **Sample PCAP datasets:** **malware-traffic-analysis.net** (free download, real malware C2 traffic captured in sandboxes, extensively documented per-sample) is the best source for a demo that needs to *look* like a real investigation rather than synthetic traffic. **CIC-IDS2017** (University of New Brunswick, free for research with site registration) gives labelled benign+attack flows with both PCAP and pre-extracted CSV features — useful if you want to demo an ML-based anomaly classifier rather than just signature matching. **MACCDC** pcaps (via Netresec, free) are real Collegiate Cyber Defense Competition captures, good for a "messy real network" flavour.
- **Disk/file-level forensics:** **Autopsy** (Apache-2.0) with **The Sleuth Kit** underneath is the standard open forensic-imaging/file-carving toolkit — relevant to ForensiX's "deleted file recovery" and "file carving from unallocated space" requirements (C1‑PS11).
- **Mobile artifact parsing:** **ALEAPP** and **iLEAPP** (both by Alexis Brignoni, open-source Python, hosted at `github.com/abrignoni`) parse Android and iOS forensic extractions respectively into HTML/TSV/timeline/KML output — this is close to a turnkey answer for ForensiX's core "recover and structure evidence" requirement; verify the exact licence text in each repo before a procurement conversation (community consensus is permissive OSS, but confirm the LICENSE file directly).
- **WhatsApp encrypted backup decryption:** community tools exist (search `wa-crypt-tools` / `whatsapp-crypt14-15-decrypt` on GitHub) to decrypt `.crypt14`/`.crypt15` backups **given the decryption key** — the hard part is legitimately obtaining that key (it lives in the Android keystore or is exportable via a rooted/ADB-backup path), which is a genuine forensic/legal-process step, not a software gap; be careful not to over-promise "we can crack WhatsApp encryption" in the pitch — you're decrypting a backup you already have lawful access to the key for, not breaking Signal-protocol encryption itself.
- **Cloud evidence (Google Takeout) parsing:** no single named library dominates here — Google Takeout exports are just structured JSON/mbox/HTML per-service, so this is realistically a custom parser you write over a weekend against a real Takeout export (Gmail as mbox, Location History as JSON, Drive file listing as JSON) rather than an existing tool you install.
- **SQLite WAL recovery for app databases:** most Android/iOS chat apps (WhatsApp, Signal, Telegram local cache) store data in SQLite with WAL (write-ahead log) journaling — deleted-but-not-yet-checkpointed rows often remain recoverable directly from the `-wal` file; standard approach is `sqlite3` CLI's `.recover` command or Python's `sqlite3` module read against the WAL directly, no specialized tool needed beyond stock SQLite ≥3.22.

## 8. Email forensics (SafeInbox)

- **EML/MSG parsing:** Python's `eml_parser` and `extract-msg` (both permissively licensed, MIT/Apache-2.0-family) handle Outlook `.msg` and standard `.eml` formats respectively — this is boilerplate, not a research problem.
- **SPF/DKIM/DMARC verification:** `checkdmarc`, `pyspf`, `dkimpy`, and `parsedmarc` (Apache-2.0/BSD family) give you programmatic SPF/DKIM/DMARC validation — directly maps to the explicit "SPF/DKIM/DMARC validation" functional requirement in SafeInbox (C1‑PS16).
- **URL/file threat intelligence:** **VirusTotal Public API** — confirmed free tier: **500 requests/day, 4 requests/minute**. This is tight for bulk scanning but fine for a live demo scanning a handful of URLs/attachments per "email."
- **URL scanning + screenshotting:** **urlscan.io** — has a free tier with per-account quotas (minute/hour/day) queryable via its own `/user/quotas` API endpoint; exact numeric limits weren't confirmed in this session (⚠️ UNVERIFIED) — check your account's quota page directly before relying on volume during the demo.
- **Phishing feeds:** **PhishTank** and **OpenPhish**'s community feed are both free (attribution required) and give you a ready-made "known-bad URL" blocklist to check incoming email links against without building your own detector from scratch — a fast way to get real true-positives into the demo.
- **Anonymisation detection (VPN/Tor/disposable email) — the honest caveat:** there's no clean open dataset/model for "this sender used a VPN/Tor," because by design these services hide exactly that signal from network-level observation. The practical approach or IP-reputation lookup (is the source IP a known Tor exit node — the Tor Project publishes a public exit-node list; is it a known VPN/hosting-provider ASN — free IP-to-ASN databases like MaxMind's free GeoLite2 exist) plus disposable-email domain blocklists (several free community lists on GitHub, e.g. `disposable-email-domains`) — genuinely buildable in a day, but should be pitched as "signals that raise suspicion," not "detects anonymisation with certainty."

## 9. Geospatial / hotspot mapping (Crime Hotspot & Predictive Patrol)

- **Mapping:** **Leaflet** (BSD-2) or **MapLibre GL JS** (BSD-3, the open fork of Mapbox GL after Mapbox went proprietary) for the front-end map; **OpenStreetMap** data via the **Overpass API** (ODbL-licensed data, free query API) for basemap/POI/road-network data — this combination needs zero paid services.
- **Hotspot detection:** **scikit-learn's DBSCAN/HDBSCAN** implementations (BSD-3) for density-based spatial clustering of incident points — HDBSCAN specifically handles variable-density clusters better than plain DBSCAN, which matters for real crime-incident spatial distributions. **PySAL** (BSD-3, the Python Spatial Analysis Library) adds proper KDE-based hotspot mapping and local spatial statistics (LISA/Getis-Ord Gi*) if you want methodologically defensible "hotspot" claims rather than just a heatmap that looks convincing.
- **Spatial indexing for scale:** **H3** (Apache-2.0, Uber's hexagonal hierarchical spatial index) — binning incidents into hexagons at a chosen resolution is a fast, well-understood way to aggregate and visualise density without re-running KDE on every zoom level; good for the "predictive patrol" framing since hex-bin density-over-time is a straightforward, explainable input to a patrol-priority score.
- **Patrol routing:** **OSRM** (BSD-2) or **Valhalla** (MIT) for self-hosted, fast routing between patrol waypoints; **OpenRouteService** (GPLv3 self-hosted, or free-quota hosted API at `openrouteservice.org`) if you'd rather not stand up your own routing server for the demo.
- **Cell-tower location data:** **OpenCelliD** (CC BY-SA 4.0, Unwired Labs) — free API key, full country-level CSV downloads, community-contributed (49,000+ contributors, ~1M new measurements/day globally) — directly relevant to both CellScope (C1‑PS15) and SIMScanner (C1‑PS14)'s tower-mapping needs. Caveat: the downloadable dataset is capped to the **last ~18 months** of measurements (older data is pruned), and India's specific coverage density is unverified in this session — spot-check your target districts before depending on it live.
- **Indian crime/incident data:** the honest picture is there is **no open incident-level Indian crime dataset** — NCRB's "Crime in India" publications (accessible via `data.gov.in` and aggregator portals like `dataful.in`) are **district/state-year aggregate counts by crime category**, not geocoded individual incidents. For a hotspot-mapping demo you will need **synthetic incident-level data** (see Section 11) calibrated to roughly match NCRB's real aggregate rates per district, rather than pretending you have real point-level FIR locations — say this explicitly in the pitch, it's a completely normal and expected constraint for this problem statement.
- **MoRTH accident data:** the Ministry of Road Transport & Highways publishes annual "Road Accidents in India" reports (aggregate, PDF/state-level) — same caveat as NCRB: useful for calibrating synthetic data realism, not usable as a live geocoded feed.

## 10. LLM plumbing (CrimeGPT, Unified Legal Platform, chatbots)

- **Local runtimes:** **Ollama** (MIT) is the fastest path to "a chat model running locally with an API" — one command pulls and serves a quantised GGUF model. **llama.cpp** (MIT) is the underlying low-level engine if you need more control (custom quantisation, embedding a model directly in an app). **vLLM** (Apache-2.0) is the right choice only if you need real throughput serving multiple concurrent requests with a GPU — overkill for a single-demo-machine hackathon booth, but worth naming if the pitch discusses production scaling.
- **Which small open models actually handle Indian legal/administrative text:** there is no dedicated "Indian legal LLM" that's both small and genuinely strong — the realistic options are (a) a general strong small model (e.g., a Llama-3/Qwen/Gemma-class 7–8B instruct model) run through a **RAG pipeline grounded in actual bare-act/judgment text** so the model isn't relying on parametric legal knowledge at all, or (b) **Airavata** (7B, Hindi-instruction-tuned, AI4Bharat) if the interaction needs to be natively Hindi-first rather than English-with-Hindi-translation. **For CrimeGPT/Unified Legal Platform, RAG-over-real-text is the correct architecture regardless of model choice** — a base LLM's memorised knowledge of BNS/BNSS sections will be unreliable and is exactly the kind of hallucination risk that matters most in a police-facing legal tool.
- **RAG stack:** **LlamaIndex** or **LangChain** (both MIT) for orchestration; **ChromaDB** (Apache-2.0, embedded, zero-ops) for a quick local vector store, or **Qdrant** (Apache-2.0, has a proper server + good filtering) if you want something closer to production-shaped; **FAISS** (MIT) if you'd rather skip a vector-DB abstraction entirely and index embeddings directly.
- **Indian legal corpora — the real access picture:**
  - **Indian Kanoon API** (`api.indiankanoon.org`) — the largest practically-accessible corpus (30M+ orders/judgments claimed), but access is gated behind their own terms: **public-private key authentication per request**, **mandatory "Powered by IKanoon" attribution on any downstream rendering**, and an explicit **"AS IS," no-warranty** clause — treat it as usable for a demo/prototype but read the terms page (`api.indiankanoon.org/terms`) before assuming bulk redistribution rights.
  - **OpenNyAI** (EkStep Foundation, `github.com/OpenNyAI`) — an actual open-source NLP pipeline purpose-built for Indian legal text: legal Named Entity Recognition and judgment "rhetorical role" structuring (identifying which sentences are facts vs. holding vs. reasoning, etc.) — this is a genuinely differentiated, ready-to-use component that most hackathon teams won't know about, worth highlighting.
  - **NJDG (National Judicial Data Grid)** — the official near-real-time case-status database for Indian courts, but it's exposed as a **public dashboard**, not a documented bulk-download API — ⚠️ UNVERIFIED whether programmatic bulk access exists; plan on demo-scale manual/scraped samples rather than a live NJDG integration.
  - **BNS/BNSS/BSA bare-act text** — the actual statute text (Bharatiya Nyaya Sanhita, Bharatiya Nagarik Suraksha Sanhita, Bharatiya Sakshya Adhiniyam, which replaced IPC/CrPC/Evidence Act in 2024) is public-domain government text, obtainable from the Ministry of Law & Justice / India Code portal (`indiacode.nic.in`) as PDF — this is the single most important thing to actually chunk-and-embed for a legal-RAG demo, since it's unambiguous, small (a few hundred sections), and gives you ground-truth citations to show judges.
  - **Nyaya Setu** — note this is **not a dataset or open project**: it's the Ministry of Law & Justice's own **WhatsApp-based citizen legal-helpline chatbot**, launched 1 January 2026. Relevant as a "here's the government's own comparable initiative" reference point in your pitch, not as a component you integrate.
- **OCR-to-RAG for scanned FIRs:** pipeline is PaddleOCR/Surya OCR (see Section 1) → text cleanup → chunk → embed → same vector-store stack as above. The realistic failure mode to plan for: Indian FIRs are frequently handwritten or poor-quality scans/photocopies mixing Gujarati/Hindi/English — budget for visibly wrong OCR output on your worst sample and show the pipeline's confidence/flagging behaviour rather than claiming clean end-to-end automation.
- **If venue internet is allowed:** Claude/OpenAI/Gemini hosted APIs are dramatically stronger than any locally-runnable open model for this use case (especially for Hindi/Gujarati legal reasoning) and worth having as a fallback path — but design the demo to **not depend on live internet**, given the explicit "offline-capable" requirement pattern across several PS and the well-known unreliability of hackathon venue wifi (see Section 11).

## 11. Demo infrastructure realities

- **Offline-capable design:** every component chosen above that matters for the live demo should have a **local fallback that requires zero internet**: local Whisper/IndicConformer instead of a cloud ASR API, a pre-downloaded Ollama model instead of a hosted LLM API, a pre-cached OFAC/Elliptic/NCRB dataset instead of a live fetch, pre-scraped Reddit/Telegram samples instead of live API calls during judging. Build the "impressive" path to work offline first; treat any live-internet feature as a bonus that degrades gracefully (visibly falls back, doesn't crash) if wifi drops.
- **Docker packaging:** `Docker` + `docker-compose` (Docker Engine is Apache-2.0) is explicitly requested as a deliverable ("Deployment instructions or Docker container") in nearly every Category 1 PS — budget real time for this, it's graded, not optional polish. A `docker-compose.yml` that brings up your DB + backend + frontend with one command is worth more evaluation credit than an extra ML feature.
- **Synthetic data generation:** **Faker** (MIT) is the standard Python library for generating realistic fake names/addresses/phone numbers/transactions; it has locale support (`fake = Faker('en_IN')` gives Indian-flavoured names/addresses/phone formats) which is directly useful for Mule Accounts/IntelliBank/CryptoTrack/Big-Data-tool demo data. For domain-specific synthetic data — CDRs, IPDR, FIR-like text, bank transaction graphs with realistic mule patterns (rapid in/out, layering, round-tripping) — there's no off-the-shelf generator; write a small script that uses Faker for the identity fields and hand-codes the *pattern logic* (e.g., inject N accounts with the exact red-flag behaviours listed in the official PS text — "frequent penny transactions," "big amount in short time," "consecutive same-amount credit/debit") so your detection demo has guaranteed true positives to find.
- **How to demo convincingly without real police data:** (1) generate synthetic data whose statistical shape is calibrated against real public aggregates where you have them (NCRB district-year crime counts, MoRTH accident aggregates) so a "hotspot" or "trend" demo isn't obviously arbitrary; (2) for anything requiring real content style (deepfake clips, phishing emails, dark-web-style listings), use small, clearly-labelled **your-own-created or public-domain** samples — never scrape or present real victim data, and never pass off synthetic data as real to the judges; (3) keep a visible "SYNTHETIC / DEMO DATA" watermark or banner in the UI — police-hackathon judges specifically watch for teams being careless about this distinction, and being upfront about it reads as more professional, not less impressive.

---

## Sources

- [AI4Bharat on HuggingFace](https://huggingface.co/ai4bharat)
- [AI4Bharat on GitHub](https://github.com/AI4Bharat)
- [ai4bharat/indic-conformer-600m-multilingual (HF model card)](https://huggingface.co/ai4bharat/indic-conformer-600m-multilingual)
- [AI4Bharat/IndicTrans2 (GitHub)](https://github.com/AI4Bharat/IndicTrans2)
- [Vistaar: Diverse Benchmarks and Training Sets for Indian Language ASR (arXiv)](https://arxiv.org/pdf/2305.15386)
- [AI4Bharat/vistaar (GitHub)](https://github.com/AI4Bharat/vistaar)
- [IndicContextEval benchmark (arXiv)](https://arxiv.org/pdf/2606.19157)
- [Airavata: Introducing Hindi Instruction-tuned LLM](https://ai4bharat.github.io/airavata/) / [arXiv:2401.15006](https://arxiv.org/abs/2401.15006)
- [Bhashini APIs — Pre-requisites and Onboarding](https://bhashini.gitbook.io/bhashini-apis/pre-requisites-and-onboarding)
- [ULCA GitHub](https://github.com/bhashini-dibd/ulca)
- [pyannote/speaker-diarization-3.1 (HF model card)](https://huggingface.co/pyannote/speaker-diarization-3.1)
- [SYSTRAN/faster-whisper (GitHub)](https://github.com/SYSTRAN/faster-whisper)
- [Indic-OCR tessdata comparison](https://indic-ocr.github.io/tessdata/)
- [tesseract-ocr/tessdata Gujarati.traineddata](https://github.com/tesseract-ocr/tessdata/blob/main/script/Gujarati.traineddata)
- [Comparison of Existing vs New Model of Tesseract OCR for Gujarati (ResearchGate)](https://www.researchgate.net/publication/387017594_Comparison_of_Existing_Versus_New_Model_of_Tesseract_OCR_for_the_Gujarati_Language)
- [SCLBD/DeepfakeBench (GitHub)](https://github.com/SCLBD/DeepfakeBench)
- [Celeb-DF (GitHub)](https://github.com/yuezunli/celeb-deepfakeforensics)
- [Why Lab Benchmarks Fail Real-World Deepfake Detection (Reality Defender)](https://www.realitydefender.com/insights/lab-benchmarks-ineffective-in-deepfake-detection)
- [Beyond the Benchmark: Generalization Limits of Deepfake Detectors in the Wild (UC Berkeley)](https://www.ischool.berkeley.edu/sites/default/files/bb_paper.pdf)
- [clovaai/aasist (GitHub)](https://github.com/clovaai/aasist)
- [eurecom-asp/RawGAT-ST-antispoofing (GitHub)](https://github.com/eurecom-asp/RawGAT-ST-antispoofing)
- [lab260/AASIST3 (HF model card)](https://huggingface.co/lab260/AASIST3)
- [InsightFace official site — licensing](https://www.insightface.ai/) / [deepinsight/insightface (GitHub)](https://github.com/deepinsight/insightface)
- [Indian Number Plates Dataset (HF)](https://huggingface.co/datasets/Dataclusterlabspvtltd/indian-number-plates-dataset)
- [datacluster-labs/Indian-Number-Plates-Dataset (GitHub)](https://github.com/datacluster-labs/Indian-Number-Plates-Dataset)
- [sanchit2843/Indian_LPR (GitHub)](https://github.com/sanchit2843/Indian_LPR)
- [llava-hf/LLaVA-NeXT-Video-7B-hf (HF)](https://huggingface.co/llava-hf/LLaVA-NeXT-Video-7B-hf)
- [Etherscan API — Rate Limits](https://docs.etherscan.io/support/rate-limits)
- [GoldRush (Covalent)](https://goldrush.dev/)
- [Elliptic Data Set (Kaggle)](https://www.kaggle.com/datasets/ellipticco/elliptic-data-set)
- [git-disl/EllipticPlusPlus (GitHub)](https://github.com/git-disl/EllipticPlusPlus)
- [0xB10C/ofac-sanctioned-digital-currency-addresses (GitHub)](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses)
- [bhemen/OFAC-SDN-analysis (GitHub)](https://github.com/bhemen/OFAC-SDN-analysis)
- [Maltego — What is Maltego Graph Community Edition (CE)?](https://docs.maltego.com/en/support/solutions/articles/15000018947-what-is-maltego-graph-community-edition-ce-)
- [Maltego Products and Plans](https://docs.maltego.com/en/support/solutions/articles/15000036759-maltego-products-and-plans)
- [Telegram API Terms of Service discussion (tdlib/td #1941)](https://github.com/tdlib/td/issues/1941)
- [TDLib termsOfService reference](https://core.telegram.org/tdlib/docs/classtd_1_1td__api_1_1terms_of_service.html)
- [Reddit API Pricing 2026 (Prowlo)](https://prowlo.com/blog/reddit-api-pricing)
- [X (Twitter) API Cost Breakdown 2026 (twitterapi.io)](https://twitterapi.io/blog/x-api-cost-breakdown-2026)
- [abrignoni/iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [LEAPPs — Digital Forensics Tools](https://leapps.org/)
- [CIC-IDS2017 dataset (UNB)](https://www.unb.ca/cic/datasets/ids-2017.html)
- [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)
- [Public PCAP files for download (Netresec, incl. MACCDC)](https://www.netresec.com/?page=PcapFiles)
- [VirusTotal — Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)
- [urlscan.io — API Rate Limits](https://docs.urlscan.io/pages/api-rate-limits)
- [NCRB Crime Statistics — India Data Portal](https://ckandev.indiadataportal.com/dataset/crime-statistics)
- [data.gov.in — National Crime Records Bureau (NCRB)](https://www.data.gov.in/ministrydepartment/National%20Crime%20Records%20Bureau%20(NCRB))
- [OpenCelliD — Downloads](https://www.opencellid.org/downloads.php)
- [Indian Kanoon API — Terms and Conditions](https://api.indiankanoon.org/terms/) / [Documentation](https://api.indiankanoon.org/documentation/)
- [OpenNyAI/Opennyai (GitHub)](https://github.com/OpenNyAI/Opennyai)
- [Nyaya Setu WhatsApp legal helpline (Angel One News)](https://www.angelone.in/news/economy/save-7217711814-nyaya-setu-whatsapp-service-for-free-legal-guidance)
- [C2PA + SynthID 2026 adoption overview (c2paviewer.com)](https://c2paviewer.com/articles/openai-google-c2pa-synthid-2026)
- [AI Watermark Detection 2026: C2PA vs SynthID vs Metadata (EyeSift)](https://www.eyesift.com/faq/ai-watermark-detection-2026-c2pa-content-credentials-google-synthid-meta-watermarking-policy-comparison/)

## Recommended default stack

If you only trust one column of this whole document, trust this one — it's the set of components with (a) confirmed permissive-or-clearly-scoped licences, (b) confirmed CPU-viability for at least a degraded demo path, and (c) no dependency on a paid/rate-limited external API for the core demo loop.

| Layer | Pick | Why |
|---|---|---|
| Speech-to-text | **faster-whisper** (`distil-large-v3`) + **AI4Bharat IndicConformer-600M** for Gujarati-specific runs | MIT, CPU-viable, no API key, no internet dependency |
| Translation | **IndicTrans2 distilled (200-320M)** | MIT, small enough for CPU, all 22 scheduled languages |
| Diarisation | **pyannote.audio 3.1** | MIT, CPU-default, one free HF token needed (get it Day 1) |
| OCR | **PaddleOCR** (fallback: Tesseract `guj.traineddata`) | Apache-2.0, meaningfully more accurate than Tesseract on Indic scripts |
| Object detection + tracking | **YOLO11 + ByteTrack** | Fastest path to a working CCTV demo; note AGPL for procurement |
| Video search | **OpenCLIP + FAISS** | MIT/MIT, CPU-viable at demo scale, no training needed |
| Graph analytics | **NetworkX + Neo4j Community** | Explicitly named in the official PS text — judges will recognise it |
| Fast local analytics | **DuckDB** | The realistic answer to every "petabyte-scale search" ask at hackathon scale |
| Entity resolution | **Splink** | MIT, purpose-built, directly maps to "link accounts across identifiers" |
| Crypto tracing | **Blockstream Esplora + Etherscan (free tier) + Elliptic dataset (Kaggle) + OFAC SDN parser** | All free, no paid dependency, gives a real trained classifier + real sanctions hits |
| Local LLM + RAG | **Ollama + LlamaIndex/LangChain + ChromaDB**, grounded in **actual BNS/BNSS/BSA bare-act text** | Zero-internet-capable, avoids hallucinated legal citations |
| Packaging | **Docker Compose** | Explicitly graded as a deliverable across most PS |
| Demo data | **Faker (`en_IN` locale)** + hand-coded pattern injection for red-flag scenarios | Guarantees your detection logic has real true positives to find on demo day |

## Traps — things that look easy but will burn your 36 hours

1. **"We'll fine-tune a model."** You will not have time to fine-tune anything meaningful in 36 hours with a hackathon-quality dataset. Use pretrained weights as-is, or at most do prompt/few-shot adaptation. Any fine-tuning line in your plan is a red flag for your own schedule.
2. **Deepfake detection generalisation.** The single most likely embarrassment on demo day: a judge uploads their own video/image and your detector confidently gets it wrong (cross-dataset AUC drops of 20-50 points are the *documented norm*, not an edge case). Pre-curate your demo examples, show a calibrated/uncertain trust score rather than a binary verdict, and say the generalisation limitation out loud before a judge discovers it.
3. **Face-recognition weight licences.** InsightFace's popular `buffalo_l`/ArcFace weights are non-commercial-research-only — fine for the hackathon itself, but if you pitch this as production-ready for police procurement without flagging the licence, that's a credibility hit with any technically literate judge. Say "these weights need a commercial licence for deployment" proactively.
4. **Dark-web crawling scope creep.** Do not build a live, unfiltered .onion crawler and run it in front of judges — CSAM exposure and the general legal ambiguity of live dark-web interaction is a real risk, not hackathon theatre. Use Ahmia as a seed index and pre-captured/curated sample pages.
5. **X/Twitter API cost surprise.** X's free tier is gone for new developers as of Feb 2026 — a team that assumes "we'll just hit the Twitter API" will discover mid-hackathon that it now costs real money per read/post. Default to Reddit/Mastodon/Bluesky, or pre-scraped samples.
6. **Telegram account bans mid-demo.** Telethon-based scraping can get the demo account rate-limited or banned by Telegram if you hit it hard while testing the night before — provision your API ID/hash and a dedicated demo account early, and cache your dataset rather than scraping live on stage.
7. **Treating NCRB/data.gov.in as incident-level data.** It's aggregate district/state-year counts. A hotspot-mapping demo built on the assumption of geocoded incident points will hit a wall — plan for synthetic incident data from the start, don't discover this on hour 30.
8. **Bhashini API as a load-bearing dependency.** The onboarding flow is confirmed and free, but published rate limits/SLA are not — do not architect a live demo where the Bhashini API is the only path to working ASR/MT; always have a local model as the real fallback.
9. **Assuming Covalent/Bitquery are perpetually free.** Covalent's "free tier" is a 14-day/25k-credit trial, not an ongoing free plan — pull and cache your crypto data early rather than depending on live API calls that may start erroring by day 2.
10. **Elasticsearch licence surprise.** It's explicitly named in the official Big Data PS suggested-tools list, but it hasn't been OSI-approved open source since 2021 (SSPL/Elastic License 2.0). If "open source" is part of your pitch's value proposition, swap in OpenSearch (Apache-2.0) — same API surface, zero functional cost.
11. **Underestimating Docker packaging time.** It's an explicit graded deliverable in nearly every Category 1 PS, and teams reliably leave it for the last hour. A working `docker-compose up` is worth deliberately protecting time for.
12. **WhatsApp "decryption" over-promising.** You can decrypt a `.crypt14/.crypt15` backup only if you already have the key (from the device keystore or an ADB-accessible path) — pitching this as "we break WhatsApp encryption" misstates both the tech and the legal posture. Frame it as backup decryption given lawful key access.
13. **Gujarati/code-mixed accuracy expectations.** Every ASR/NLP number in the published benchmarks is for clean, single-language audio/text. Real call recordings with Gujarati-Hindi-English code-switching and background noise will perform measurably worse than any headline WER/accuracy figure you cite — build a visible confidence/review step into any transcript-facing feature rather than presenting transcripts as ground truth.
