# 152 — Deep-research prompts for ChatGPT, Grok and Gemini

**Status:** 19 Sep 2026. Three prompts, one per tool, each aimed at what that tool can reach and the
others cannot. They do not overlap with each other, or with the three research agents run from this
repository the same day, which cover: (1) Android packer and protector markers, (2) static
indicators for the malware families already in our MalwareBazaar corpus, and (3) Android platform
and Play policy restrictions and the workarounds malware uses.

| Tool | Assigned domain | Why this tool |
|---|---|---|
| **Grok** | Indian APK-fraud campaigns, Mar–Sep 2026, as posted on X | real-time access to X, where CERT-In, I4C, state cyber cells and researchers post first |
| **Gemini** | malware whose logic is not in DEX (Flutter, React Native, Xamarin/.NET MAUI, native code), from conference talks and Google/Mandiant/VirusTotal research | Google index plus YouTube, where the talks live |
| **ChatGPT** | academic methods: per-rule false-positive control, rule mining, ML that proposes while rules establish, abstention; open rule sets and their licences | long-form reading of papers and PDFs |

Paste each prompt as it stands. Every prompt asks the tool to cite only sources it actually opened —
answers that come back without URLs should be treated as unverified.

---

## Prompt 1 — Grok

```
I maintain an open-source Android APK examination engine used for cybercrime forensics by police in
India. It never executes samples; it reads the manifest, signing certificate and DEX code, and it
only reports harm when a documented combination of behaviours is present. On 200 recent
MalwareBazaar APK samples it detected 34%. I need India-specific ground truth to test it against.

TASK: Search X (Twitter) for posts between 1 March 2026 and today about malicious Android APKs
used in fraud against people in India. Prioritise posts by: CERT-In, the Indian Cybercrime
Coordination Centre (I4C) and @Cyberdost, state police cyber cells (especially Gujarat, Maharashtra,
Karnataka, Telangana, Delhi, Kerala, Tamil Nadu), bank security teams, and named independent
malware researchers.

For each distinct campaign, extract only what the posts actually state:
- lure / app display name (e.g. "RTO e-challan", "PM Kisan", "wedding invitation", bank KYC update,
  electricity bill, pay commission calculator, customer support),
- package name(s),
- SHA-256 / SHA-1 / MD5 hashes, copied character for character,
- distribution channel (WhatsApp, Telegram, SMS, social-media ads, fake Play pages, QR codes),
- the genuine app or organisation being impersonated,
- behaviour described (OTP/SMS theft, call forwarding via USSD, screen sharing, accessibility
  abuse, notification interception, contact harvesting, self-forwarding to the victim's contacts),
- C2 indicators (domains, IPs, Telegram bot usernames or tokens as posted),
- reported losses or arrest details if given.

OUTPUT: a markdown table, one row per campaign: date | poster (@handle) | post URL | lure name |
package name(s) | hashes | channel | impersonates | behaviour | C2 indicators. After the table, list
any hashes that appear in more than one independent post.

RULES:
- Only include a post you actually retrieved, with its URL. No URL, no row.
- Never infer, complete or reconstruct a hash, package name or domain. If a post shows a
  partial or blurred hash, write "partial" rather than filling it in.
- Mark whether each campaign is corroborated by a second independent poster.
- Out of scope, do not research: global malware family write-ups, Android platform restrictions,
  packer technology, academic papers. Others are covering those.
```

---

## Prompt 2 — Gemini

```
I maintain an open-source Android APK examination engine used for police cybercrime forensics.
It is static-only: it indexes the app's DEX bytecode with androguard, attributes each call to the
app or to a bundled SDK, and reports harm only for documented combinations of behaviours. Its blind
spot I need to understand: malware whose logic does not live in DEX at all.

TASK: Research Android malware and static-analysis evasion that moves logic OUT of DEX bytecode,
using (a) conference talks 2023–2026 — Black Hat, DEF CON, Virus Bulletin, BotConf, RSA, REcon,
Android Security Symposium, Google I/O — including the talk videos and slides on YouTube, and
(b) research published by Google Threat Intelligence, Mandiant, VirusTotal, and the Android
Security and Privacy team.

Cover specifically:
1. Malware built with cross-platform frameworks — Flutter (Dart AOT code in libapp.so), React
   Native / Hermes (index.android.bundle), Xamarin and .NET MAUI (managed assemblies), Unity,
   Cordova/Capacitor (JavaScript in assets). Named families, years, and how analysts extracted the
   logic statically.
2. Malware that keeps its payload in native code (JNI .so libraries) or in encrypted assets
   decrypted by native code.
3. For each framework: the concrete static artefacts that reveal which framework an APK uses
   (file paths, library names, magic bytes), and the open-source tools that decompile or
   disassemble it (e.g. for Dart AOT snapshots, Hermes bytecode, .NET assemblies), with licences.
4. Any published measurement of how common framework-based apps are among malware versus
   legitimate apps.

OUTPUT: a markdown report with a table: framework or technique | named malware families (year) |
static artefact that identifies it | tool to recover logic (licence) | source URL | source type
(talk video / slides / vendor blog / paper). Then a short section: which of these a DEX-only
analyser misses entirely, stated as your assessment.

RULES:
- Cite only sources you actually opened; for talks give the video or slide URL and the timestamp
  where the claim is made if possible.
- Do not invent family names, years or tool names. Write "not found" rather than guess.
- Out of scope, do not research: DEX packers and protectors (e.g. Jiagu, Bangcle, DexGuard),
  Android permission and platform restrictions, Indian fraud campaigns, academic ML detection
  methods. Others are covering those.
```

---

## Prompt 3 — ChatGPT (deep research)

```
I maintain an open-source (MIT-licensed) static Android malware examination engine used in police
forensics, where every verdict must be explainable in court. Design constraints you must respect:
- A verdict is an evidence tier, not a score. A rule may raise the tier only if it fired on zero
  apps of a legitimate reference corpus; its benign firing count and exact 95% upper bound are
  published with every finding.
- Measured today: 0 false positives on 299 held-out legitimate apps, but only 34% detection on 200
  recent MalwareBazaar APK samples. Most misses fire only one capability.
The question is how to raise detection without giving up either property.

TASK: Survey peer-reviewed and preprint literature (2021–2026; IEEE S&P, USENIX Security, CCS,
NDSS, ACSAC, RAID, ESORICS, EuroS&P, TOPS, TIFS, TDSC, arXiv) on:
1. Explainable static Android malware detection that reports false-positive rates per rule or per
   feature, not only per model.
2. Automatic mining of detection rules or signatures from malware corpora with explicit control of
   benign false positives (association-rule mining, API-sequence mining, generated YARA-style
   rules, rule learning), including how the benign corpus was built.
3. Hybrid designs where a machine-learning model only proposes candidates and a separate,
   auditable layer decides — including abstention / reject options, conformal prediction and
   credibility-based rejection for malware (e.g. the Transcend / TESSERACT line of work), and how
   drift is handled.
4. Honest reported recall of static, rule-based or signature-based Android detectors on recent
   malware, with dataset, year and time-aware evaluation.
5. Open rule and indicator sets for Android (for example Quark-Engine rules, APKiD rules, MobSF
   rules, community YARA sets): what they contain, and each one's licence, stated from the licence
   file.

OUTPUT: an annotated bibliography. For each work: full citation with DOI or arXiv ID | venue and
year | dataset (size, years, sources) | reported false-positive rate and recall, and on what split
| the one idea transferable to the design above | limitations. Then a ranked list of the three
ideas most likely to raise detection while keeping per-rule benign firing at zero, with reasoning,
labelled as your assessment.

RULES:
- Cite only works you actually opened. Give DOIs or arXiv IDs; do not invent citations, numbers or
  authors. If a number is not in the paper, write "not reported".
- Distinguish what a paper measured from what it claims or speculates.
- Out of scope, do not research: packer/protector detection, specific malware family write-ups,
  Android platform restrictions, Indian campaigns, cross-platform framework malware. Others are
  covering those.
```

---

## What to do with the answers

Paste each answer into `research/external/` as `grok_2026-09.md`, `gemini_2026-09.md`,
`chatgpt_2026-09.md`, unedited. Treat every row as unverified until its URL has been opened and
checked; hashes from Grok are to be looked up on MalwareBazaar before any is used as ground truth.


Grok:
**India-specific malicious Android APK fraud campaigns from X posts (1 March 2026 – 19 September 2026).**  

Only posts actually retrieved via X search/tools are included (with their URLs). No inferences, reconstructions, or completions of hashes, package names, or domains. Partial/blurred items marked as such. Technical IoCs (hashes, packages, C2) are rare in the retrieved official/priority posts; most are awareness/advisory style. Global family analyses, academic papers, and non-X sources are out of scope per rules.

### Campaigns table

| date | poster (@handle) | post URL | lure name | package name(s) | hashes | channel | impersonates | behaviour | C2 indicators | corroborated by 2nd independent poster? |
|------|------------------|----------|-----------|-----------------|--------|---------|--------------|-----------|---------------|---------------------------------------|
| 2026-03-17 | @IndianCERT | https://x.com/IndianCERT/status/2033948381924733406 | RTO Challan.apk / RTO E Challan.apk / MParivahan.apk (or similar) | (none stated) | (none stated) | WhatsApp, SMS, Telegram, random websites | Official RTO / government e-Challan notifications | Multi-stage dropper; shows in App Drawer then prompts “Install Update”; seeks SMS/phone/call permissions + background + VPN; steals financial credentials via fake screens; reads SMS for OTPs sent to attacker server | (none stated) | Yes (multiple independent awareness posts reference the same CERT-In advisory / theme, e.g. @SSOIndia, others) |
| 2026-08-31 / 2026-09-09 | @Cyberdost | https://x.com/Cyberdost/status/2094431518508843516 (and follow-ups e.g. https://x.com/Cyberdost/status/2097694016125206612) | Night Play, Reloop, Kyss, Vimo, Rivo, Nexo, Vixa (and similar variants) | (none stated) | (none stated) | Social-media ads (Facebook/Instagram) → websites serving pornographic content | Adult-content / entertainment / free-video apps | Misuse Accessibility permissions; take control of device; enable unauthorised financial transactions; may install additional apps / VPN | (none stated) | Yes (multiple @Cyberdost posts + independent news/awareness posts referencing the I4C advisory) |
| 2026-09-08 | @SSOIndia | https://x.com/SSOIndia/status/2097331720148160690 | Fake e-Challan / RTO or traffic challan APK | (none stated) | (none stated) | WhatsApp | RTO / traffic challan | Steal money and sensitive information (case cited: Trichy victim lost nearly ₹2 lakh) | (none stated) | Yes (aligns with CERT-In RTO/e-Challan campaign) |
| 2026-09-14 | @AnkitNayak_dev | https://x.com/AnkitNayak_dev/status/2099474648748708001 | ₹1,000 e-Challan | (none stated) | (none stated) | SMS | MoRTH / RTO | (warns against clicking/installing the APK; links to fake site parivahanchallangov[.]vercel[.]app) | (none stated) | Partial (same broad e-Challan theme as CERT-In / @SSOIndia) |
| Various (e.g. Jun–Sep 2026 references in posts) | Multiple (e.g. news/awareness accounts citing police actions) | Examples: posts referencing Ahmedabad/Gujarat cases (gas-bill theme) and general APK warnings | Sabarmati Gas Bill Update.apk / gas meter update / gas disconnection threat; general bank KYC / courier / wedding / job offers | (none stated in retrieved posts) | (none stated) | WhatsApp (primary), SMS, Telegram | Sabarmati Gas Limited / gas companies; banks (KYC); courier/customs | Remote access / control of phone; intercept OTPs/SMS; drain bank accounts (examples: ~₹6.68 lakh Ahmedabad victim; ~₹99k Lucknow case; self-spreading noted in some police reports) | (none stated) | Yes for gas-bill theme (multiple independent police/news references); general APK warnings widespread |

### Hashes appearing in more than one independent post
None. No SHA-256 / SHA-1 / MD5 hashes (or package names) for Android APKs were stated character-for-character in the retrieved priority or independent posts within the date range. (One Windows stealer post contained hashes but is out of scope as non-Android/APK.)

**Notes on coverage and limitations (strictly per rules):**  
- Priority accounts (@Cyberdost / I4C, @IndianCERT, state cyber cells, banks) mostly issued behavioural/lure warnings without technical IoCs.  
- Distinct campaigns with usable detail are the RTO/e-Challan dropper (CERT-In) and the social-media adult-app Accessibility abuse cluster (I4C/@Cyberdost). Gas-bill / KYC / courier themes appear repeatedly in police-linked awareness but lack package/hash/C2 in the posts themselves.  
- Many posts are generic “never install unknown APKs” advice and do not qualify as distinct campaigns with the required fields.  
- No post provided C2 domains/IPs/Telegram bots/tokens for these Android campaigns.  

For ground-truth testing, the CERT-In advisory page linked from the 17 Mar 2026 post and the I4C advisory linked from the @Cyberdost posts remain the strongest official India-specific sources retrieved. Further targeted searches on specific state cyber-cell handles or researcher accounts may surface additional samples if needed.

Gemini:
Non-DEX Android Malware Logic: Static Evasion Vectors, Framework Artefacts, and Forensic Recovery Methodologies
Architectural Evasion Beyond Dalvik Executable Bytecode
In mobile threat analysis and digital forensics, static examination engines historically relied on parsing Dalvik Executable (classes.dex) files to extract application opcodes, build call graphs, and map Android API invocations1. Tools such as Androguard classify malicious behaviors by identifying sensitive API calls—such as telephonic data harvesting, system service bindings, and dynamic code loading—directly within the DEX bytecode structure1. However, modern Android threat actors increasingly bypass DEX-centric static analyzers by moving application business logic, Command-and-Control (C2) communication routines, and payload execution mechanisms entirely outside the DEX execution layer2.
This architectural shift degrades the efficacy of DEX-only forensic inspection2. By leveraging cross-platform compilation frameworks, native C/C++ shared libraries, or managed execution runtimes, malware developers reduce the classes.dex binary to a minimal, visually benign bootstrap wrapper2. When an application's primary execution path resides within Ahead-Of-Time (AOT) compiled Dart snapshots, Meta Hermes bytecode binaries, packed .NET Common Intermediate Language (CIL) assemblies, or compiled Native Development Kit (NDK) shared objects, traditional DEX indexing engines register only standard framework initialization stubs and generic native library loading calls such as System.loadLibrary2. Consequently, identifying malicious intent requires forensic architectures capable of parsing non-DEX static artefacts, recovering framework-specific bytecode or assembly, and evaluating low-level binary structures2.
Cross-Platform Framework Evasion Mechanics
Cross-platform software development kits allow developers to compile applications for Android and iOS from a unified codebase2. However, the underlying compilation pipelines conceal execution semantics from conventional Android reverse engineering tools2. Rather than emitting standard Dalvik bytecode, these frameworks output native shared libraries, custom register-based bytecodes, or packed managed assemblies2.
Flutter and Dart Ahead-Of-Time Snapshots
Applications developed using Google's Flutter framework compile Dart code directly into native machine code Ahead-Of-Time (AOT) for release distributions2. On the Android platform, the resulting application package contains a lightweight Java bootstrap while the application logic is stored inside an ELF shared library named libapp.so, located in the lib/<abi>/ directory alongside the Flutter runtime engine libflutter.so2.
The compiled application code inside libapp.so is organized around serialized snapshot structures, specifically _kDartIsolateSnapshotInstruction and _kDartIsolateSnapshotData4. Static analysis of libapp.so using generic disassemblers is complicated by the custom register mapping and calling conventions used by the Dart Virtual Machine on ARM64 architectures4:
Register x15: Serves as the custom Dart VM Stack Pointer4.
Register x26: Holds the pointer to the current Thread structure4.
Register x27: Serves as the Object Pool Pointer (PP), managing indirections to objects, constants, and string literals4.
Register x28: Acts as the Heap Base Pointer, used to decompress compressed pointers at runtime4.
Because string definitions, type arguments, and object references are resolved via offsets relative to the Object Pool Pointer (x27), conventional static disassemblers fail to establish direct cross-references between data definitions and instruction sites4. Furthermore, because the Dart AOT snapshot structure lacks public formal specifications and evolves across SDK versions, parsers written for one runtime version frequently fail on binaries compiled with newer toolchains4.
To extract logic statically, analysts utilize specialized utilities such as Blutter, which parses the Dart snapshot header, identifies runtime offset tables, and generates symbolicated C-like pseudocode alongside assembly annotations4. Alternative frameworks like reFlutter modify the Flutter engine runtime to dump class structures, method names, and object pools during execution2.
Threat actors have adapted Flutter to evade detection across several documented malware campaigns4:
MoneyMonger (aka SpyLoan) (2022): A predatory loan malware family that encapsulates string encryption and configuration parsing inside libapp.so4. The application invokes Android permissions and telephonic harvesting routines by passing messages across Flutter Platform Channels (MethodChannel) to a minimal Java receiver4.
FluHorse (2022–2023): Discovered posing as toll-payment utilities in Eastern Asia, FluHorse was among the first families to implement its complete operational payload—including fake login interfaces, credit card harvesting routines, and 2FA SMS interception—directly in Dart code within libapp.so4.
Riskware/Nischat (2024): Disguised as media software, Nischat utilizes libapp.so to conceal anti-analysis routines and AES-encrypted HTTP communications while sideloading secondary APK payloads4.
React Native and Hermes Bytecode
React Native applications execute application logic written in JavaScript2. In modern deployments, JavaScript source code is compiled into Hermes Bytecode (HBC) using Meta's Hermes JavaScript engine to optimize application cold-start performance10.
When compiled with Hermes, the primary application logic is stored in assets/index.android.bundle, while the execution engine is packaged as lib/<abi>/libhermes.so10. Unlike standard JavaScript bundles that store ASCII text, a Hermes bundle is a binary file containing custom register-based opcodes, string tables, and function headers16.
Static inspection of assets/index.android.bundle using text-based or Dalvik tools is ineffective16. Disassembling Hermes bytecode requires specialized tools such as hbctool or hermes-dec, which parse the binary header, extract control flow graphs, and disassemble instructions into Hermes Assembly (HASM)7. ReuNify further assists reverse engineering by reconstructing control-flow semantics from HASM back into higher-level representations20.
The threat family RelayNFC (2024) demonstrates this evasion vector16. Operating as a payment card relay tool, RelayNFC stores its entire control loop within assets/index.android.bundle compiled as Hermes bytecode16. The payload initializes persistent WebSocket connections, presents phishing overlays requesting credit card PINs, and intercepts near-field communication (NFC) Application Protocol Data Unit (APDU) frames to relay live transaction data to an attacker server—all while exhibiting zero initial detections on VirusTotal due to the absence of executable code in classes.dex16.
Xamarin and .NET MAUI Managed Assemblies
Microsoft's Xamarin and its successor, .NET MAUI (Multi-platform App UI), execute C# source code on top of the Mono or .NET runtime5. In these applications, classes.dex contains proxy stubs that invoke native runtime libraries such as libmonodroid.so or libnetcoremain.so5. The actual application logic resides within managed .NET assemblies (DLLs) stored inside the assemblies/ directory5.
In modern .NET MAUI Android deployments, individual managed assemblies are frequently compressed and packed into unified binary container files, such as assemblies/assemblies.blob or assemblies/assemblies.arm64-v8a.blob5. These blob files contain the packed C# Common Intermediate Language (CIL) byte streams for the application5.
Because static DEX analyzers evaluate only the Java bootstrap layer, they observe only the initialization of the .NET host environment5. To recover the operational logic, analysts must extract the managed DLLs from the assemblies.blob container using extraction scripts or Ghidra plugins, and subsequently decompile the recovered CIL bytecode using .NET decompilers such as ILSpy or dnSpy2.
Malware campaigns discovered in 2025 targeting financial users in Asia leverage .NET MAUI as an architectural packer5. Posing as banking applications (e.g., fake IndusInd Bank apps) or social platforms, these threats conceal multi-stage dynamic loaders inside encrypted C# assemblies5. Upon execution, the managed code decrypts dynamic CIL payloads stored within the assemblies/ directory, harvested device contacts, SMS messages, and photos, and transmitted stolen data across encrypted raw TCP sockets—completely bypassing antivirus engines focused on DEX or ELF native scanning5.
Unity Engine and IL2CPP Compilation
Android games and graphical utilities built on the Unity engine predominantly utilize the Intermediate Language 2 C++ (IL2CPP) scripting backend for performance and binary protection21. When compiled with IL2CPP, C# scripts are translated into C++ code and compiled into a native shared library11:
Native Application Binary: lib/<abi>/libil2cpp.so
[cite: 11, 22, 23]
Metadata Container File: assets/bin/Data/Managed/Metadata/global-metadata.dat
[cite: 11, 22, 24]
The global-metadata.dat binary file contains structural metadata required by the runtime for object reflection, string evaluation, and method invocation21. The file header is identified by a 32-bit magic number signature at offset 0:

This signature is followed by a 32-bit integer defining the IL2CPP metadata version, alongside offset tables pointing to class definitions, field offsets, and string literal indices22.
Disassembling libil2cpp.so independently produces stripped native machine code devoid of function or class names21. To reconstruct the application structure, analysts utilize metadata extraction tools such as Il2CppInspector or Il2CppDumper6. These utilities parse global-metadata.dat, map string tables and type definitions back to their corresponding virtual addresses in libil2cpp.so, and generate symbolicated header files, C# dummy code, and script files for Ghidra or IDA Pro6.
Threat actors utilize trojanized Unity applications—such as modified variants of Europe Truck Simulator 2 (2023)—to hide ad-fraud routines, background downloaders, and credential scrapers within native C++ routines inside libil2cpp.so, bypassing standard DEX analysis pipelines21.
Cordova and Web-Based Frameworks
Apache Cordova and Capacitor allow mobile applications to be developed using HTML5, CSS3, and JavaScript, rendering UI components within an Android WebView25. The application source code is stored directly within the application's assets archive:
Root Web Directory: assets/www/
[cite: 27]
Primary Entry Document: assets/www/index.html
Scripting Files: assets/www/js/*.js, assets/www/cordova.js, assets/www/cordova_plugins.js
[cite: 27]
Configuration parameters and custom plugin interfaces bridging Java and JavaScript are defined in res/xml/config.xml. DEX inspection engines observe only the generic WebView wrapper container26. The operational logic—including dynamic HTML form injection, DOM manipulation, and network requests—resides inside the JavaScript files under assets/www/26. Analysts extract these web assets directly from the APK ZIP structure and analyze the JavaScript source using browser developer tools or static JavaScript linters3.
The SOVA Banking Trojan (2021–2023) utilized Apache Cordova to wrap its financial fraud capabilities26. SOVA stored its control logic inside JavaScript files within assets/www/, combining web communication channels with Android Accessibility Services to inject phishing overlays over banking apps and execute unauthorized fund transfers26.
Native JNI Payloads and Memory Decryption Routines
Beyond cross-platform frameworks, malware authors frequently embed malicious functionality directly inside compiled C/C++ libraries using the Java Native Interface (JNI), or store encrypted binary payloads within static asset directories3.
Dynamic JNI Method Registration
Standard DEX static analyzers detect native code integration by identifying Java methods declared with the native modifier and searching for exported C symbols in .so files that match the standard JNI naming convention:

To defeat this static linkage analysis, threat actors employ dynamic JNI registration3. When the native shared library is loaded via System.loadLibrary, the Android runtime executes the library's JNI_OnLoad function3. Within JNI_OnLoad, the native code invokes the JNI environment function RegisterNatives:

This call dynamically maps Java native method signatures to arbitrary, unexported C function addresses at runtime3. Consequently, the ELF symbol table of the .so library contains no exported symbol names corresponding to the Java class methods, leaving static DEX call-graph analyzers unable to associate Java entry points with their underlying native C implementations3.
In-Memory Payload Decryption via Anonymous Memory File Descriptors
To prevent static file scanners from analyzing secondary payloads stored on disk, native malware libraries decrypt hidden payloads directly into RAM using Linux system calls5.
The native shared library extracts an encrypted binary blob from assets/ or res/raw/3. The native library then executes the Linux memfd_create system call to allocate an anonymous, RAM-backed memory file descriptor:

The native code decrypts the payload bytes (such as an encrypted DEX file or secondary shared object) directly into the file descriptor fd28. The malware then passes /proc/self/fd/<fd> to dalvik.system.InMemoryDexClassLoader or executes the ELF binary directly from memory28. Because the decrypted payload exists strictly within volatile memory and is never written to the physical storage filesystem, disk-based static file scanners cannot inspect the operational binary28.
Several high-profile Android malware families rely on native JNI payloads and dynamic memory decryption3:
Xenomorph (2022–2024): Utilizes native .so components to execute string decryption routines, anti-analysis checks, and dynamic payload loading, evading DEX analysis engines3.
Octo / Octo2 (2024): Incorporates native shared objects to handle Remote Access Trojan (RAT) commands, device takeover (DTO) automation, and low-latency video streaming, concealing C2 handlers outside the DEX layer28.
Chameleon (2023–2024): Uses native JNI routines and memfd_create memory allocations to unpack secondary payloads in RAM, disable biometric prompts, and automate background Accessibility Service interactions28.
Anatsa (aka TeaBot) (2023–2025): Disguised within utility applications, Anatsa uses native shared libraries to execute multi-stage payload decryption, pulling down targeted overlay configurations at runtime30.
Statistical Measurement and Framework Prevalence
Empirical measurements published across industry security reports and academic research demonstrate a clear divergence between framework usage in legitimate software versus malicious applications4.
Legitimate Market Distribution
Data presented at Virus Bulletin 2024 indicates that cross-platform frameworks comprise a measurable segment of the overall mobile ecosystem4:
Flutter: Accounts for approximately  of all published Android applications, and reaches  market share among top-downloaded and newly released Google Play Store applications4.
React Native / Unity / Cordova: Maintain stable adoption in enterprise, mobile gaming, and utility app categories, representing a combined estimated  of general app store distributions.
Malware Ecosystem Telemetry
Threat intelligence data published by Google, Kaspersky, and Zimperium highlights a rapid increase in framework-based and non-DEX malware distribution12:
Sideloaded Malware Growth: Google Play Protect identified 27 million malicious sideloaded applications in 2025, up from 13 million in 2024—representing a  year-over-year increase32. Sideloading represents the primary distribution channel for cross-platform and packed native malware families (such as MoneyMonger, RelayNFC, and MAUI banking trojans)5.
Financial Malware Volume: Kaspersky recorded 255,090 banking trojan installation packages in 202532. Malware families utilizing cross-platform wrappers (e.g., .NET MAUI, Flutter) represent the fastest-growing sub-category of financial threats, deliberately selected by threat actors to evade automated app-store scanners and static triage pipelines5.
Initial Evasion Rates: In initial telemetry collections, newly deployed framework-compiled malware families (such as RelayNFC in React Native/Hermes and MAUI-based banking variants) exhibited 0% detection rates across standard VirusTotal multi-engine scans upon initial release, demonstrating the real-world efficacy of non-DEX static evasion5.
Technical Mapping Matrix

Framework or Technique
Named Malware Families (Year)
Static Artefact That Identifies It
Tool to Recover Logic (Licence)
Source URL
Source Type
Flutter (Dart AOT)
MoneyMonger / SpyLoan (2022)4, FluHorse (2023)4, Riskware/Nischat (2024)4
lib/<abi>/libapp.so, assets/flutter_assets/
[cite: 2, 4, 8]
Blutter (Open-Source)4, reFlutter (MIT)2, Doldrums (MIT)8
https://filestore.fortinet.com/fortiguard/research/flutter.pdf
[cite: 4]
Presentation Slides (Virus Bulletin 2024)4
React Native (Hermes)
RelayNFC (2024)16
assets/index.android.bundle, lib/<abi>/libhermes.so
[cite: 10, 15, 16, 17]
hbctool (MIT)7, hermes-dec (GPL-3.0)19, ReuNify (Apache-2.0)20
https://cyble.com/blog/relaynfc-nfc-relay-malware-targeting-brazil/
[cite: 16]
Vendor Blog16
Xamarin / .NET MAUI
Fake IndusInd Bank / Fake SNS Campaigns (2025)5
assemblies/ directory containing .dll or .blob files (e.g., assemblies.blob)5
ILSpy (MIT), dnSpy (GPL-3.0), Ghidra (Apache-2.0)2
https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/
[cite: 5]
Vendor Blog5
Unity (IL2CPP)
Europe Truck Simulator 2 Trojan (2023)23, Honkai Impact Target (2021)24
lib/<abi>/libil2cpp.so, assets/bin/Data/Managed/Metadata/global-metadata.dat (Magic: AF 1B B1 FA)4
Il2CppInspector (MIT)6, Il2CppDumper (Apache-2.0)21
https://www.usenix.org/system/files/sec22-zuo.pdf
[cite: 22]
Academic Paper (USENIX Security 2022)22
Apache Cordova / Capacitor
SOVA Banking Trojan (2021–2023)26
assets/www/index.html, assets/www/js/cordova.js, res/xml/config.xml
[cite: 27]
Chrome DevTools (BSD-style), JADX (Apache-2.0)3
https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/accessibility-services-abuse.html
[cite: 26]
Technical Documentation / Research Wiki26
Native JNI / Memory Decryption
Xenomorph (2022–2024)3, Octo2 (2024)28, Chameleon (2023–2024)28, Anatsa (2023–2025)30
Stripped .so files in lib/<abi>/, encrypted blobs in assets/ or res/raw/, JNI RegisterNatives, memfd_create calls3
Ghidra (Apache-2.0), radare2 (LGPL-3.0), GDB/LLDB (NCSA/Apache-2.0)2
https://dokumen.pub/the-android-malware-handbook-detection-and-analysis-by-human-and-machine-1718503318-171850330x-9781718503304-9781718503304-9781718503311.html
[cite: 3]
Forensic Reference Manual / Book3

Forensic Assessment of DEX-Only Static Analysis Blind Spots
An open-source Android examination engine that relies exclusively on indexing DEX bytecode (classes.dex) via Androguard suffers complete visibility loss when analyzing modern non-DEX malware variants2. Specifically, a DEX-only analyzer entirely misses the following critical threat indicators and operational behaviors:
Complete Absence of Execution Logic: In Flutter (libapp.so), React Native with Hermes (index.android.bundle), .NET MAUI (assemblies.blob), and Unity IL2CPP (libil2cpp.so), the entire operational business logic is located outside the DEX file2. The DEX analyzer evaluates only generic framework bootstrap wrappers, categorizing the application as benign or incomplete2.
Invisibility of Command-and-Control (C2) Infrastructure: Hardcoded C2 domains, IP addresses, communication endpoints, and AES encryption keys embedded within Dart Object Pools, Hermes string tables, or C# assembly binaries are completely ignored by DEX-focused string extractors2.
Broken Native Call Graphs: Native routines registered dynamically via RegisterNatives within JNI_OnLoad create no static symbol linkages in DEX bytecode3. A DEX analyzer cannot trace calls from Java entry points to underlying native C/C++ functionality3.
Unexamined Web Asset Payloads: Applications built on Apache Cordova or Capacitor execute overlay phishing, DOM scraping, and session hijacking within JavaScript scripts under assets/www/26. A DEX analyzer inspects only the container WebView class, missing all malicious web routines26.
Undetected RAM-Only Decryption: Payloads decrypted into memory via memfd_create anonymous file descriptors exist strictly in volatile RAM28. Disk-based static DEX analyzers cannot inspect these dynamic payloads because unencrypted bytecode is never saved to the static APK storage28.
To maintain forensic utility against contemporary mobile threats, static analysis engines must incorporate pre-processing routines that inspect native shared libraries, asset archives, and framework metadata, routing non-DEX artefacts to specialized disassemblers before generating forensic harm reports4.
Works cited
MH-1M: A 1.34 Million-Sample Multi-Feature Android Malware, https://pmc.ncbi.nlm.nih.gov/articles/PMC12873278/
Hacking Flutter Apps: Static, Dynamic, and Beyond - Cobalt, https://www.cobalt.io/blog/hacking-flutter-apps-static-dynamic-and-beyond
The Android Malware Handbook: Detection and Analysis by Human, https://dokumen.pub/the-android-malware-handbook-detection-and-analysis-by-human-and-machine-1718503318-171850330x-9781718503304-9781718503311.html
Android Flutter Malware - Fortinet, https://filestore.fortinet.com/fortiguard/research/flutter.pdf
New Android Malware Campaigns Evading Detection Using Cross, https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/
Il2CppInspectorRedux/README.md at master - GitHub, https://github.com/LukeFZ/Il2CppInspectorRedux/blob/master/README.md
hbctool-cli 0.18 on PyPI - Libraries.io, https://libraries.io/pypi/hbctool-cli
Reversing an Android sample which uses Flutter - cryptax - Medium, https://cryptax.medium.com/reversing-an-android-sample-which-uses-flutter-23c3ff04b847
Flutter Reverse Engineering & Decompiler Guide - Guardsquare, https://www.guardsquare.com/blog/current-state-and-future-of-reversing-flutter-apps
Comprehensive Security, Privacy & Reverse Engineering Analysis, https://gist.github.com/deepdeyiitgn/d72e4560975326347b7d4a22209ada33
How to Patch a Android Unity Game - Secure77, https://secure77.de/how-to-patch-a-android-unity-game/
MoneyMonger: Predatory Loan Scam Campaigns Move to Flutter, https://zimperium.com/blog/moneymonger-predatory-loan-scam-campaigns-move-to-flutter
FrameWar Flutter Malware: Mobile Threats & Attack Infrastructure, https://alice.io/blog/flutter-malware-framewar-threat-intelligence
Inside Sinchat Flutter riskware - cryptax - Medium, https://cryptax.medium.com/inside-sinchat-flutter-riskware-797cc2046237
Penetration Testing for Flutter and React Native Apps - Simpa Labs, https://www.simpalabs.com/blog/best-pentest-companies-flutter-react-native
RelayNFC Targets Brazil - Cyble, https://cyble.com/blog/relaynfc-nfc-relay-malware-targeting-brazil/
GitHub - trilwu/secskills: Transform Claude Code into your personal, https://github.com/trilwu/secskills
Demystifying React Native Android Apps for Static Analysis, https://nzjohng.github.io/publications/papers/tosem2024_6.pdf
hermes_rs - crates.io: Rust Package Registry, https://crates.io/crates/hermes_rs/0.1.0
GitHub - DannyGooo/ReuNify, https://github.com/DannyGooo/ReuNify
How Games Counter IL2CppDumper Reverse Engineering - YouTube, https://www.youtube.com/watch?v=muDDDowyXxA
Detecting Vulnerable Payment Verification in Native Binaries of, https://www.usenix.org/system/files/sec22-zuo.pdf
VirusTotal - File - VirusTotal, https://www.virustotal.com/gui/file/f2c4d9915730567cd1b571ecba04f47c182b625375f69e1334acc70a695c70a9
Honkai Impact 3rd (Houkai 3) (IL2CPP) (Part 1), https://katyscode.wordpress.com/2021/01/17/reverse-engineering-adventures-honkai-impact-3rd-houkai-3-il2cpp-part-1/
Black Hat Asia 2014 | Briefings, https://blackhat.com/asia-14/briefings.html
Android Accessibility Service Abuse - HackTricks, https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/accessibility-services-abuse.html
Stack-Overflow-Tags-Communities/dataset/E_llda at master - GitHub, https://github.com/imansaleh16/Stack-Overflow-Tags-Communities/blob/master/dataset/E_llda
Virus, https://wokb.cz/Articles/Virus.html
Cyber Threat Post & Advisory - Varutra Consulting, https://www.varutra.com/ctp/index.php
Android Security & Malware – Telegram, https://t.me/s/androidMalware?before=2676
Security Flaw in BlueStacks Emulator for Windows Puts Millions of, https://www.varutra.com/ctp/threatpost/postDetails/Security-Flaw-in-BlueStacks-Emulator-for-Windows-Puts-Millions-of-Gamers-at-Risk/d2N4ZjJBdVgzd2FyQVhYREM3dDlCdz09
Android Malware 2026: Threats, iOS Comparison & Trends, https://www.vervali.com/blog/android-malware-statistics-2026-threat-landscape-ios-comparison-and-detection-trends/
Fortinet Reverses Flutter-based Android Malware “Fluhorse”, https://www.fortinet.com/blog/threat-research/fortinet-reverses-flutter-based-android-malware-fluhorse
.SRCINFO - aur.git - AUR Package Repositories, https://aur.archlinux.org/cgit/aur.git/tree/.SRCINFO?h=python-hbctool
bongtrop/hbctool: Hermes Bytecode Reverse Engineering ... - GitHub, https://github.com/bongtrop/hbctool

Chatgpt:

Annotated Bibliography
Alhawari et al. (2026). AI-Driven Rule-Based Feature Scoring for Explainable and Adversarially Robust Android Malware Detection. Electronics 15(10):2167. DOI:10.3390/electronics15102167. Dataset: Balanced Android APKs from AndroZoo (malware with >30 VT detections vs. benign, 85% train / 15% test split). Metrics: After scoring features via association rules (CAR), Random Forest on the scored dataset achieved 98.815% recall at 98.378% precision (nearly 0 false positives) vs. 97.778% recall on non-scored (other classifiers showed similar recall gains). Idea: Use ARM-derived rule scores to weight features for ML models, improving recall (and stability). Transferable insight: Their association-rule‑based feature selection shows how mined rules (“CARs”) can yield highly discriminative features with near-zero benign triggers (their RF recall↑1.0% while maintaining ≈0 FPs). Limitations: They report only aggregate classifier metrics, not per-rule FP rates; they rely on ML, not a purely rule‑based verdict, and their benign corpus may differ from ours (AndroZoo vs. our “reference corpus”), so rule FPs are not explicitly bounded per rule.

Si et al. (2022). Malware Detection Using Automated Generation of YARA Rules on Dynamic Features. In Science of Cyber Security (LNCS 13580), pp.315–330. Springer. DOI:10.1007/978-3-031-17551-0_21. Dataset: Unknown size (malicious and benign APKs; dynamic API call traces from sandbox). Metrics: Authors claim “effective” detection (high accuracy and precision) using automatically generated YARA rules. Exact FPR/FNs not reported. Idea: Mine frequent API‐call patterns and parameter values in malware (via RF+LR weighting) to generate YARA signatures, then use them for detection. Transferable insight: This work shows that association-patterns of API calls (including semantic parameters) can be converted into YARA rules with high precision. If adapted to static code (extracting API call sequences statically instead of from a sandbox), similar rule induction could boost coverage. Limitations: They use dynamic behavior logs (not pure static analysis), and they do not report benign false-positive counts per rule. Their benign corpus and rule evaluation methodology aren’t described in detail, so it’s unclear whether any rule hits benign apps.

Jordaney et al. (2017). Transcend: Detecting Concept Drift in Malware Classification. In USENIX Security 2017, pp.623–641. DOI:10.5555/3241094.3241166. Dataset: Drebin (2010–12) vs. Marvin (2010–14); Drebin for training (123K apps: 5,560 malware, 123K benign), Marvin split for testing (balanced malware/benign subsets). Metrics: On a drifting split (train Drebin, test Marvin), an SVM baseline had only 36% recall for malware. Transcend’s conformal filter (rejecting low-confidence predictions) improved detected malware recall from 36% to 76% (at the cost of discarding 23% of samples) while increasing precision from 61% to 89%. Idea: Use conformal prediction to abstain on “out-of-distribution” cases. A small trusted set (calibration) defines p-value thresholds that maximize F1 under an FPR constraint. Transferable insight: Rejecting low-confidence ML predictions can dramatically raise recall. In a rule-based engine context, one could analogously “reject” apps that partially match a rule but appear anomalous. The notion of strict thresholds (e.g. require 100% rule confidence) parallels our requirement of zero benign triggers. Limitations: Transcend is a learning-based framework, not a static rule generator. Its recall gain comes by discarding (“abstaining on”) some samples – this does not directly produce new positive detections. It also depends on a ML model and separate calibration step, not on mining new rules.

Yang et al. (2021). CADE: Detecting and Explaining Concept Drift Samples for Security Applications. In USENIX Security 2021, pp.2327–2344. URL: USENIX Security (2021). Dataset: Case studies on Android malware and NIDS; actual malware database from an industry partner (details not given). Metrics: Focus is on per-sample drift detection, not aggregate recall. They demonstrate CADE can flag malicious “drifting” samples and explain them. Idea: Contrastively learn a distance metric to detect individual drifting malware, then use distance-based explanations. Transferable insight: CADE shows how to identify and “explain” samples that are unlike the training set. For a rule-based engine, one could similarly maintain a “drift monitor” (e.g. if an app triggers only rare rules, flag it). Limitations: CADE is an ML/feature-space method, not directly about rule generation or static signatures. It also does not report traditional recall/FPR metrics on malware detection.

Quark-Engine (rules). Detection rule set for Android (Quark-Engine) – GPL-3.0 license. Contents: Hundreds of pattern-based rules (modules and strings) for identifying malicious behaviors and packers in Android apps (community-maintained). License: GNU GPLv3. Idea: Quark’s “open rules” illustrate how static signatures (e.g. suspicious permissions, API usage, string patterns) can encode malware traits. Limitations: Exact per-rule false-positive stats are not provided, though Quark maintains a large benign corpus to test rules. Rules are often syntactic and may miss malware that hides features; plus GPLv3 license means derived work must be open-sourced.

APKiD (rules). Android Packer/Obfuscator Signatures – dual-license (GPL-3.0 open source). Contents: Signatures (as YARA rules) for packers and obfuscators used in APKs. APKiD scans APKs (and some common native libs) to tag known packers (e.g. zipalign, upx, DexGuard, libs like Androwarn, AndrOB, Snot, etc.). License: GPL-3.0 (see LICENSE.GPL). Idea: Packager/protector fingerprints can raise evidence of malicious intent (many malware pack their code). Every packer signature in APKiD is tested on numerous benign apps; the tool claims high confidence. Limitations: Packer presence is only a probabilistic malware indicator (many benign apps also use packers for legitimate reasons), so APKiD’s detections are not strict "zero-FP" rules. The benign-firing counts of each signature are not published (the dual license suggests a for-profit model for guaranteed performance). So APKiD rules cannot directly be used as “evidence” tiers under the zero‑FP requirement without re-validation.

MobSF static rules. Mobile Security Framework rule set (Android static analysis) – GPL-3.0. Contents: MobSF includes many hardcoded checks on Android apps (e.g. dangerous permissions, insecure coding patterns, manifest misconfigurations). These are expressed as code in the static analyzer (and embedded YARA for some patterns). License: GPL-3.0. Idea: MobSF’s checks (e.g. “Internet permission + dangerous flag” or known vulnerable library signatures) could inspire new rule tiers; they have been tested on large sets of apps. Limitations: MobSF focuses on broad security issues, not explicitly on malware. Its rules have variable false-positive rates (documented in tool docs). Because it is GPL-3.0, any use or adaptation would require releasing under the same license. The exact benign-match counts of each rule are not officially published.

Community YARA rules (Android). YARA rule repositories (e.g. InQuest’s “awesome-yara”) – GNU GPLv2. Contents: Collections of YARA signatures for Android malware and behaviors (e.g. leaked trojan indicators, strings, binary patterns) gathered from security blogs and community contributions. License: GPL-2.0 (“Our YARA ruleset is under the GNU-GPLv2 license…”). Idea: These shared rule sets cover known malicious string/byte patterns and can be directly used in static scans. Many rules have been field-tested (e.g. in VirusTotal or MalwareBazaar). Limitations: Community rules vary in quality and are often not vetted on large benign corpora. Their FPRs are not usually published, so each rule might occasionally match benign code. Also, license GPLv2 requires derived work to be GPL as well.

Ranked Ideas to Improve Detection (with Zero Benign Hits)
1. Mine multi-feature association rules (“AND” signatures). Use data-mining (e.g. FP-growth or Apriori) on known malware to find combinations of capabilities, permissions, or API calls that together never occur in the benign reference set. For example, if some malware samples share both Permission A and Service B (which individually may appear in benign apps), a rule “A AND B” can catch those samples. Such rules guarantee 0 benign matches by construction. This is analogous to how Astroid/MaxSAT derives conjunctions of graph features to avoid FPs. Prior work (e.g. RFS-MD) shows association rules can identify high-suspicion feature sets; applied judiciously, we could extract many strict “multi-condition” signatures from recent malware without any benign triggers. Why promising: It directly leverages our benign corpus: any candidate rule is only accepted if it yields 0 hits on benign reference. It extends the current “single-capability” rules to more specific patterns, likely boosting recall on apps that would fire only one weak indicator. Limitations: Risk of overfitting – rules might become too specific (catch only 1–2 malware); requires careful thresholding (minimum malware support) to avoid trivial rules. Also, combinatorial explosion of feature sets must be managed.

2. Derive API-call and intent-flow signatures. Analyze Android apps’ code (or manifest intents) to find specific sequences or dataflows unique to malware. For instance, mining short API-call sequences (e.g. sendSMS→getLocation or HttpURLConnection→execShell) or uncommon intent chains that appear in multiple recent malware but never in benign apps. As in the SciSec dynamic work, one could adapt sequence-mining (or tools like APIARY) to static bytecode. Rules could be YARA-style patterns on disassembled code or manifest-driven alert sequences. Why promising: Some malware blend only one capability (like SEND_SMS), but also perform specific actions (e.g. sending SMS after obtaining device ID) that benign apps rarely do together. Capturing these behaviors would catch more malware misses. Limitations: Static extraction of reliable sequences can be tricky (due to obfuscation). Sequences must be kept short (to match across samples) and validated on benign. Also, too-long signatures may miss variants.

3. Graph-based semantic signatures (common subgraphs). Construct structural signatures by finding a small common ICC (inter-component communication) or call graph pattern among a malware family, then verify it never appears in benign apps. This follows the Astroid/Apposcopy approach: synthesize a minimal subgraph (e.g. activities + calls between them) that all family samples share. Such semantic signatures can detect code reuse beyond simple strings. Why promising: It can catch malware variants that share a workflow (e.g. data exfiltration path) without obvious capability matches. Because these signatures are structural, trivial repackaging or renaming may not evade them. Limitations: Graph mining is computationally expensive and complex; creating on-the-fly is hard for an engine. It’s more suited for offline rule development. Also, the benign guarantee requires testing on the reference corpus graph representations, which could be expensive.

In summary, enriching the rule set by mining combined malware-only features (capabilities, permissions, API sequences, or code-flow subgraphs) offers the best hope of raising detection while maintaining zero false alarms per rule. Each idea emphasizes explicit checking against the benign corpus to enforce the zero-FP constraint, preserving the evidentiary rigor of the engine.
---

## Assessment of the three answers (19 Sep 2026)

Written after reading all three. None of their claims has been treated as fact; what follows is what
each is good for and where it fails.

### Grok — a useful negative result
No SHA-256, SHA-1, MD5 or package name was produced for any Indian campaign, and Grok says so instead
of inventing one. That is the right behaviour and it settles a question: **X will not give us a
labelled Indian test set**, because the official accounts (@Cyberdost, @IndianCERT, state cyber cells)
post awareness material rather than indicators.

What it is good for is the **impersonation reference set**, which needs names, not hashes: RTO /
e-Challan, MParivahan, "Sabarmati Gas Bill Update.apk" (Gujarat), bank KYC, courier, wedding
invitations, and the fake host `parivahanchallangov[.]vercel[.]app`.

Not verifiable from here: x.com refuses automated fetching, so the post IDs, the loss figures
(₹2 lakh Trichy, ₹6.68 lakh Ahmedabad) and the corroboration column stand unchecked.

### Gemini — right about the blind spot, unreliable about its sources
The substantive claim is that an engine which indexes only `classes.dex` is blind to apps whose logic
lives elsewhere: Flutter (`lib/*/libapp.so`), React Native with Hermes
(`assets/index.android.bundle`), .NET MAUI (`assemblies/*.blob`), Unity IL2CPP (`lib/*/libil2cpp.so`),
Cordova (`assets/www/`), and native payloads registered through `RegisterNatives` or decrypted into
`memfd_create` descriptors. For such an app androguard sees a bootstrap stub — which is exactly what
our misses look like.

Defects, stated plainly:
* **Numbers are missing from several statistics** ("approximately ___ of all published Android
  applications", "a ___ year-over-year increase"). Unusable as written.
* **The works-cited list contains junk** — a Claude Code skills repository, a Stack Overflow tags
  dataset, an Arch Linux `.SRCINFO`, Black Hat *Asia 2014*. The list cannot be trusted wholesale.
* The 27M / 13M sideloading figures trace to a marketing blog, not to Google.

The framework artefact paths, however, are checkable without trusting any citation, so the claim was
tested on our own corpora instead (below).

### ChatGPT — the most directly usable
Its first ranked proposal is our own gate, automated: **mine conjunctions of features that occur in
malware and never in the benign corpus, and accept a rule only at zero benign firings**. We now have
a 500-app feature table to mine. It cites the Astroid / Apposcopy line for semantic signatures, which
is the right precedent.

It also confirms independently what the packer audit found: Quark (GPL-3.0), APKiD (GPL-3.0),
MobSF (GPL-3.0) and community YARA sets (GPL-2.0) **cannot be embedded in an MIT-licensed engine**.

Transcend (USENIX 2017) and CADE (USENIX 2021) are real; the 2026 MDPI paper is unverified.

### Measured on our own corpus, not taken on trust
`tools/framework_scan.py` reads ZIP entry names only. On the 300 held-out F-Droid apps:

| Framework | Benign apps |
|---|---|
| Flutter | 28 / 300 |
| Cordova / web | 8 / 300 |
| React Native (Hermes) | 6 / 300 |
| React Native (other) | 1 / 300 |
| **any framework** | **42 / 300 (14.0%)** |

So being a framework app is ordinary and can never raise a tier. The question worth answering is
whether the 127 misses are **enriched** above this 14% baseline; that is measured on the malicious
corpus once the feature extraction finishes.
