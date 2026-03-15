# GAMA Framework — Quick Start

**Greyware Analysis and Mitigation Approach v1.0**
CenturiaLabs · ClickSafe UAE

## Avvio

```bash
python3 main.py
```

## Dipendenze esterne (non Python)

| Tool     | Uso                              | Installazione              |
|----------|----------------------------------|----------------------------|
| apktool  | Decompilazione APK + smali       | https://apktool.org        |
| jadx     | Sorgente Java da APK             | https://github.com/skylot/jadx |
| frida    | Instrumentazione dinamica        | pip install frida-tools    |
| zeek     | Analisi pcap                     | https://zeek.org           |

## Struttura workspace

```
workspace/
└── 20260314_1200_nome-app/
    ├── meta.json           ← stato sessione
    ├── findings.jsonl      ← tutti i findings (append-only)
    ├── static/
    │   ├── apktool_out/    ← decompilazione apktool
    │   ├── jadx_out/       ← sorgente Java
    │   ├── phase0_intake.json
    │   ├── manifest_analysis.json
    │   ├── uri_scheme_scan.json
    │   └── sdk_fingerprint.json
    ├── dynamic/
    │   ├── gama_uri_[pkg].js
    │   ├── gama_ids_[pkg].js
    │   ├── gama_persist_[pkg].js
    │   └── observations.log
    ├── network/
    │   ├── dns.log         ← Zeek
    │   ├── conn.log        ← Zeek
    │   └── dns_classification.json
    ├── rules/
    │   ├── dns_sinkhole.txt
    │   ├── gama.zeek
    │   └── gama.rules
    └── report/
        └── report_YYYYMMDD_HHMM.json
```

## Tecniche GAMA

| ID         | ATT&CK Mobile       | Descrizione                          |
|------------|---------------------|--------------------------------------|
| GAMA-T001  | T1637.002 (proposto)| URI scheme custom bypass             |
| GAMA-T002  | T1407               | Post-install silent payload          |
| GAMA-T003  | T1624.003 (proposto)| Background task persistence          |
| GAMA-T004  | T1665               | Domain fronting via CDN              |
| GAMA-T005  | nuovo               | JNI policy bypass                    |
| GAMA-T006  | nuovo               | Premium tier visual illusion         |

## Classificazione findings

- **Class-A**: operativo, proporzionato alla funzione dichiarata
- **Class-B**: sproporzionato, eccede la funzione ma non ingannevole
- **Class-C**: nascosto, usa mezzi tecnici per evitare rilevamento
- **Class-D**: ingannevole, contraddice dichiarazioni esplicite della privacy policy
