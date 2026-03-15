# GAMA Framework

**Greyware Analysis and Mitigation Approach**

An analyst-first CLI for structured Android greyware investigation.

> Technology collects. The analyst interprets.

## The GAMA Ecosystem

| Tool | Role |
|------|------|
| **GAMA Framework** (this repo) | Interactive analyst workspace — 7-phase methodology |
| [GAMA-Intel](https://github.com/psychomad/gama-intel) | Automated static analysis pipeline |
| [GAMA-Deep](https://github.com/psychomad/gama-deep) | ML anomaly scoring (Rust) |
| GAMA-Community *(coming soon)* | Shared finding knowledge base |

## Features

- 7-phase structured methodology
- Logic-based URI scanner — scores by context, not signatures
- SDK fingerprinting — 40+ known SDKs
- Finding management — Class A/B/C/D classification
- Enforcement rule generation — DNS sinkhole, Zeek, Snort/Suricata
- XAPK/APKS support

## Quick Start
```bash
git clone https://github.com/psychomad/gama-framework
cd gama-framework
python3 main.py
```

## The 7 Phases

| Phase | Name | Output |
|-------|------|--------|
| 0 | Intake & hypothesis | Investigation hypothesis before touching code |
| 1 | Static analysis | URI schemes, SDK fingerprint, manifest |
| 2 | URI schemes & IPC | Custom URI channel deep analysis |
| 3 | Dynamic setup | Frida script generation |
| 4 | Network analysis | DNS classification, post-termination delta |
| 5 | Correlation & classification | Class A/B/C/D |
| 6 | Enforcement rules | DNS sinkhole, Zeek/Snort rules |
| 7 | Report & disclosure | ATT&CK-mapped findings |

## Classification

| Class | Definition |
|-------|------------|
| A | Operational — proportionate to declared purpose |
| B | Disproportionate — collects more than declared |
| C | Concealed — evasion techniques (URI bypass, JNI, encoding) |
| D | Deceptive — contradicts privacy policy |

## Real Analysis: Airport Empire Idle

22 suspicious URI schemes found in a 140MB idle game:
```
mv://        score 12  — Mintegral SDK IPC bypass → CENT-2026-001 (Class-C)
mraid://     score 12  — IAB WebView ad protocol
applovin://  score 12  — AppLovin SDK
tcp://       score 11  — Anomalous in WebView context
global://    score  8  — 99 occurrences in 2 files
```

## GAMA Techniques

| ID | Name | ATT&CK Mobile |
|----|------|---------------|
| GAMA-T001 | Custom URI scheme IPC bypass | T1637.002 (proposed) |
| GAMA-T002 | Post-install silent payload | T1407 |
| GAMA-T003 | Background task persistence | T1624.003 (proposed) |
| GAMA-T004 | Domain fronting via CDN | T1665 |
| GAMA-T005 | JNI policy bypass | proposed |
| GAMA-T006 | Premium tier visual illusion | proposed |
| GAMA-T007 | Encoded string obfuscation | T1406 |

## Authors

**CenturiaLabs / ClickSafe UAE** · audit.centurialabs.pl

## License

MIT
