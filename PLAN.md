# PLAN — Restructure awesome-csirt + add CI

> Handoff document. Any agent can resume from the **Progress log** at the bottom.
> Rules: (1) write/update the step here *before* acting; (2) never delete a file or a link — move, merge, or dedupe only; (3) keep token use low (use `grep`/`awk`/`git mv`, not full-file reads) but never trade accuracy; (4) one commit per step on branch `restructure`; (5) run the step's **Verify** before marking it done.

## Goal

A clean, logically grouped awesome list for CSIRTs: easy to find topics and files, CI-checked, nothing lost.

## Baseline facts (2026-11-12, commit `eb09c1e`)

- 30 tracked files. `README.md` = 3,735 lines, ~3,322 list items, 120 headings in flat/odd order (e.g. `Fun`, `psyops`, `Links` mixed with core topics).
- Only 4 files are linked from README (`books.md`, `botnets.md`, `CVEsPoCs.md`, `SecurityProjects.md`) and those use **absolute** links to old repo name `github.com/Spacial/csirt/...`. All other files are orphaned (unreferenced).
- Known defects: `img/sqlinjwaf.jpeg` referenced (README:1602) but missing; badge uses dead `cdn.rawgit.com`; typo `Pyhon.md`; intro typo `pull requests*- ;)`; no CI, no CONTRIBUTING.
- `PoCs/` holds a compiled ELF (`cve-2021-33910-crasher`) and a `.zip` — keep, but document.

## Target layout

```
README.md              index + curated list (regrouped, with TOC)
CONTRIBUTING.md        how to add links, format rules
LICENSE
lists/                 topic pages (was root *.md)
  books.md  botnets.md  blockchain.md  cert-br.md (CERT.md)  cves-pocs.md (CVEsPoCs.md)
  misp.md  news.md  pdf-analysis.md  python.md (Pyhon.md)  security-projects.md
  sql-injection.md  buffer-overflow.md (0verfl0w/BufferLinks.md)  windows-tweets.md (windows/tweets.md)
pocs/                  (was PoCs/) + README.md index with warnings, one line per file
scripts/               existing + xencrypt_example.ps1, + README.md index
intel/                 emotet-c2-2019.txt (was C2/2019_emotet.txt)
assets/img/            privescwin.jpg (was windows/)
.github/workflows/     lint.yml, links.yml
.github/               markdownlint + lychee configs
```

All moves via `git mv` (history preserved). Note: external deep links to old paths will break — accepted; README links become relative.

## Target README section order (CSIRT-centric)

Move existing sections **verbatim** (content unchanged); only change heading levels/names. Source heading → new parent:

1. **Getting Started** — Books, Resources, Training and Certifications, Conferences and Slides, Sans, Articles, Sources, Other Repos, News (→ lists/news.md)
2. **Incident Response** — Incident Response, Links (generic collections; triage later), Hashing, Risk Assessment and Vulnerability Management, Guidelines, Patching, CERT.br (→ lists/cert-br.md)
3. **Threat Intelligence** — Threat Hunting, MISP, APT, IoCs, OSINT (+Webscraping, Chats), psyops
4. **Detection & Monitoring** — Blue Team, SIEM, DNS, WAFs, Purple Team
5. **Forensics** — Forensics, PDF, Email Headers, Distros, Volatility, Steganography
6. **Malware Analysis** — Malware Analysis (+all subs), Botnets (→ list), Reverse Engineering (Decompilers, Yara, Ghidra)
7. **Vulnerabilities & Exploitation** — CVEs, Vulnerability, Exploits, Payloads, ShellCodes, WebShells, Web Exploitation (+Burp Suite), Bug Bounty, Buffer overflow (→ list)
8. **Offensive Security** — Pentesting, Reconnaissance, Enumeration, Reporting, Red Team, Command & Control (C2), Frameworks, Exfiltration, Phishing, Social Engineering
9. **Platforms** — Operating Systems, Windows (AD, Mimikatz, Powershell, Office/O365), macOS/iOS, Linux/*Nix, UEFI, Mobile, Android, Cloud (AWS, Azure, GCP), Browsers (+Addons)
10. **Hardware, ICS & Radio** — Archs, Hardware, ARM, ICS (SCADA), Radio, Satellite, Phreak, Blockchain (→ list)
11. **Defense & Secure Development** — Hardening, WebServers, Credentials, Tokens, Secure Programming (+Web Training, SAST, Secure Web dev, Formal Analysis, Fuzzing, API, REST), Configs, Privacy
12. **Tools** — Tools, Note-taking, Kali, IP Reputation, Shell tools, Search Engines, VPN, Secure Sharing
13. **Practice** — CTFs, CTFs tools
14. **Miscellaneous** — General, Fun

## Steps

### S0 — Branch + baseline snapshot

- `git switch -c restructure`
- Baseline is reproducible from commit `eb09c1e` (`git show eb09c1e:<file>`); a copy was saved to scratch (not committed): sorted list of every URL in all `.md` files → `baseline_urls.txt`; `git ls-files` → `baseline_files.txt`; counts.
- **Verify:** files exist, counts recorded in Progress log.

### S1 — Move files to target layout

- `git mv` per Target layout (14 md, PoCs→pocs, C2→intel, windows/privescwin.jpg→assets/img, xencrypt→scripts). Remove emptied dirs.
- **Verify:** `git ls-files | wc -l` = 30; every baseline file maps to exactly one new path (write map table into Progress log).

### S2 — Fix internal links

- Rewrite absolute `github.com/Spacial/csirt/(blob|tree)/master/<old>` and any repo-relative refs (incl. in `lists/cves-pocs.md` → pocs/*) to new **relative** paths.
- **Verify:** script resolving every relative link in all `.md` → 0 missing (except README:1602 image, handled in S5).

### S3 — Regroup README sections

- Use an `awk`/Python script (not manual editing) that splits README by heading into blocks and re-emits them in Target order with new heading levels. Unmapped headings → fail loudly.
- Add TOC (top-level groups + subsections) and a **Repository files** section linking every `lists/`, `pocs/`, `scripts/`, `intel/` file (fixes orphans).
- **Verify:** sorted URL multiset of README before == after (only additions = new internal links). No section lost: heading count ≥ baseline.

### S4 — Dedupe

- (Refined 2026-11-12) Remove only **identical lines** that are childless top-level items **within the same section** (keep first). Cross-section duplicates and same-URL/different-text items are kept (cross-listing aids discovery) and listed in `DUPLICATES report` in Progress log for owner review. Record each removal.
- **Verify:** set of unique URLs unchanged vs. baseline.

### S5 — Small fixes

- Badge → `https://awesome.re/badge.svg`; fix intro typo; README:1602 missing image → replace image embed with text/link (search history `git log --all -- img/` first; restore if found).
- Add `pocs/README.md` (file, CVE, language, ⚠ warning for binary/zip), `scripts/README.md`, `CONTRIBUTING.md`.
- **Verify:** relative-link check 0 missing.

### S6 — CI

- `.github/workflows/lint.yml`: `DavidAnson/markdownlint-cli2-action` (pinned version) with relaxed `.markdownlint-cli2.jsonc` (disable line-length etc.) on PR/push — **blocking**.
- `.github/workflows/links.yml`: `lycheeverse/lychee-action` (pinned) — relative/internal links **blocking** on PR; full external check weekly cron, opens an issue, non-blocking. `.lycheeignore` for known flaky domains; exclude `pocs/`.
- **Verify:** run `markdownlint-cli2` and `lychee --offline` locally (via npx/brew if available) → pass; else note "unverified locally".

### S7 — Final verification + handoff

- Compare against baseline: all 30 files present (moved), unique-URL set ⊇ baseline, CI configs valid YAML.
- Write summary in Progress log; open PR only when user asks. Decide with user whether to keep or delete this PLAN.md.

## Decisions (user, 2026-11-12)

- External dead links: **report only** (weekly CI issue). Do not prune.
- Generic `## Links` section (45 items): **redistribute** each item to the most suitable section (step S3b). Its subsections (Incident Response, Hashing) move as blocks per Target order.

### S3b — Redistribute `## Links` items (after S3)

- Extract the 45 top-level items (with their nested sub-items) of `## Links`; assign each to a target section; write the mapping table (item → section) in Progress log **before** moving.
- Items with no good fit → `Getting Started > Collections`.
- **Verify:** README URL multiset unchanged; `## Links` heading gone.

## Progress log

| Step | Status | Notes |
|---|---|---|
| Plan | done | written 2026-11-12 |
| S0 | done | branch `restructure`. Baseline @eb09c1e: 30 files; URLs in all .md = 4812 (4667 unique); README URLs = 3645, 77 duplicated URLs |
| S1 | done | 30/30 files tracked, all as renames (git mv). Map: root *.md → lists/ (Blockchain→blockchain, CERT→cert-br, CVEsPoCs→cves-pocs, News→news, PDFAnalysis→pdf-analysis, Pyhon→python, SecurityProjects→security-projects, sql_injection→sql-injection; books/botnets/misp same name); 0verfl0w/BufferLinks.md→lists/buffer-overflow.md; windows/tweets.md→lists/windows-tweets.md; windows/privescwin.jpg→assets/img/; PoCs/→pocs/ (2-step rename, case-insensitive FS); C2/2019_emotet.txt→intel/emotet-c2-2019.txt; xencrypt_example.ps1→scripts/ |
| S2 | done | Rewrote 5 absolute `Spacial/csirt` links in README → relative; cves-pocs.md crasher/.zip links → ../pocs/; fixed scheme-less links (malvuln, helviojunior); `./#Cloud`→`#cloud`. Remaining missing (handled S5): `img/sqlinjwaf.jpeg`, `./web/oneliners.md` (never in this repo's history). cuneiform `](...)` at README ~1745 is code, not a link (false positive). cves-pocs.md:30 links 3 `PoCs/ubuntu_*.c` files **deleted by owner in f4eb82f** — not restored; ask user. |
| S3 | done | Script `regroup.py` (scratch; logic = Target order table above, Links→"Collections", Tools→"General Tools", group IR renamed "Incident Response & Coordination", Forensics group "Digital Forensics"). 114/114 headings mapped. Verify: README URLs 3642→3642, 0 removed/0 added; 0 content lines lost (+91 new = TOC + Repository Files). Added Contents + Repository Files (links every lists/ file, pocs/, scripts/, intel/, assets/img/). |
| S3b | done | Verified: 42 items moved to 20 sections, README URLs 3642→3642 (0 removed). Mapping (42 top-level items; sub-items move with parent; new section `### Cryptography` in Defense & Secure Development before Configs): FIRST → Incident Response; Cert.BR → Incident Response; SANS Pen-Testing → Pentesting; Some [list] → Other Repos; APT & CyberCriminal → APT - Advanced Persistent Threat; Encoding vs. → Cryptography; Shodan → Search Engines; CriminalIP → Search Engines; hacking-tutorials → Other Repos; crypto] → Cryptography; tink → Cryptography; SPLOITUS → Exploits; Vulmon → Vulnerability; Vulert → Vulnerability; CIS SecureSuite → Hardening; CRYPTO101 → Cryptography; SMHasher → Hashing; CPDoS → Web Exploitation; cacao → Incident Response; cti-documentation → IoCs; The 4th in the 5th → Articles; SOCless → Blue Team; Open CSIRT Foundation → Incident Response; Global Forum on Cyber → Incident Response; Ten strategies → Blue Team; my-infosec-awesome → Other Repos; How to Secure Anything → Hardening; Metasploitable3 → CTFs; Institute for Security and Technology → General; NIST'S CYBERSECURITY → Guidelines; pluto-eris → Cryptography; cset → Risk Assessment and Vulnerability Management; comply → Risk Assessment and Vulnerability Management; Illustrated X.509 → Cryptography; OSCAL → Guidelines; DWF → CVEs; OASIS Common Security Advisory → Vulnerability; notrandom → Cryptography; OpenEX → Incident Response; NCSI → General; THE EVOLUTION OF TRUST → Fun; Cybersecurity] → Other Repos |
| S4 | done | Removed 13 identical same-section duplicate lines (rustdsplit, beebug, Orange GHE chain, code white Liferay, Black Lotus Labs, arty-hlr Defender bypass, Top 20 PLC, NCSC TLS, pigaios, build reproducibility gist, Dizzy-legacy, cherrytree, SwiftnessX). README URLs 3642→3627; unique URLs lost: 0. DUPLICATES report: 63 URLs still appear more than once (cross-section or different text) — kept; regenerate with `grep -oE 'https?://[^) >"]+' README.md \| sort \| uniq -d`. |
| S5 | done | Badge → awesome.re; intro typo fixed + CONTRIBUTING link; missing `img/sqlinjwaf.jpeg` embed → text note; dead `[local copy](./web/oneliners.md)` removed (external link kept). Added pocs/README.md, scripts/README.md, intel/README.md, CONTRIBUTING.md (descriptions checked against file headers). Found `pocs/teste.cpp` byte-identical to `CVE-2017-1000112_container_escape.c` — kept, flagged for owner. Relative links: 0 missing (only false positives). |
| S6 | done | Added `.markdownlint-cli2.jsonc` (relaxed: MD004/005/007/013/033/034/040/045/046/050 off, MD024 siblings_only), `--fix` applied: whitespace-only changes in 10 files (verified non-whitespace content identical). `.github/workflows/lint.yml` (markdownlint-cli2-action@v20, blocking) and `links.yml` (lychee-action@v2: offline internal check blocking on push/PR; weekly + manual external check, non-blocking, opens issue via create-issue-from-file@v5). Local verify: markdownlint-cli2 0.17.2 → 0 errors; lychee 0.24.2 --offline → 0 errors; YAML parses. |
| S7 | done | vs eb09c1e: 30/30 original files present (22 renamed, README modified, 0 deleted) + 8 added (CONTRIBUTING, 3 folder READMEs, lint config, 2 workflows, PLAN). Unique URLs 4667→4666; only 6 missing, all intentional (old rawgit badge + 5 absolute Spacial/csirt links now relative). Pending owner: keep/delete PLAN.md; restore 3 `ubuntu_*.c` PoCs deleted in f4eb82f?; drop duplicate `pocs/teste.cpp`?; open PR? |
