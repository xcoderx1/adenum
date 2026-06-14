# Changelog

## v1.2.1 — Correctness fixes

### Fixed
- **Low-priv -> high-priv path-finding gaps (the core BloodHound use case).**
  The transitive path-finder built group membership only from each group's
  `Members` array, so it ignored (a) `PrimaryGroupSID` — a user's Domain Users
  membership, and everything reachable through it — and (b) the implicit
  Authenticated Users / Everyone memberships every account holds. These are the
  *most common* starting points for a low-privileged user, so the most common
  escalation paths were structurally invisible. Both are now edges in the graph.
  Also added a **low-priv quick-win pass**: abusable rights held by Everyone /
  Authenticated Users / Domain Users / Domain Computers are reported directly
  (what *any* authenticated user can abuse, independent of the current account),
  with MachineAccountQuota-aware wording for Domain Computers and real
  GPO/OU-abuse commands. (Verified: on a real export this surfaced a Domain
  Computers -> GPO control path that the Members-only graph missed entirely.)
- **ADCS findings now carry the real CA and template names.** Every ESC finding
  previously emitted the identical placeholder
  `certipy req ... -ca CA_NAME -template TEMPLATE`, so the report looked the same
  for ESC1/ESC4/ESC8/etc. The module now parses certipy's JSON (via jq) and emits
  one finding per (ESC, template) and per (ESC, CA) with the actual names and an
  ESC-appropriate command (e.g. ESC4 rewrites the template then requests; ESC8/11
  are relay commands). Falls back to the text scan if JSON/jq are unavailable so a
  vulnerability is never dropped. (Verified against a real certipy export.)
- **BloodHound collection robustness.** bloodhound-python auto-selects the PDC
  and connects to it by name; when that name resolved to an unreachable IP
  (alternate DC / IPv6 record / split-horizon DNS) the bind timed out and the
  whole auto-exploitation feature produced nothing — observed on a real run
  where every direct LDAP query to the supplied DC succeeded. The collector now
  targets the reachable DC explicitly with `-dc <rootDSE dnsHostName>`, adds
  `--dns-tcp`, optionally pins that FQDN to the supplied DC IP in /etc/hosts
  (`ADENUM_PIN_DC_HOSTS=1`, root only, reversible), and on failure prints the
  exact manual collect-and-parse commands instead of a bare error.
- **LOW-severity findings were dropped from the summary.** Some checks emit
  `LOW` (selective-auth, net-session), but the counters, `recount_findings`, and
  both the HTML and text severity summaries only tracked
  CRITICAL/HIGH/MEDIUM/INFO — so LOW findings were invisible in the totals (and
  unfilterable in the HTML). LOW is now a first-class severity end to end.
- **BloodHound transitive paths now reach the Domain object.** `_is_high_value()`
  only recognised privileged-group RIDs and builtin admin SIDs, so the domain
  object (whose SID carries no privileged RID) was never treated as a target.
  The common, high-impact path *"member of a group that has WriteDacl/GenericAll
  on the domain → DCSync"* was therefore silently dropped. It is now emitted with
  its per-hop bloodyAD steps. (Regression-tested with a synthetic
  group→WriteDacl→Domain dataset.)
- **`--quick` now actually skips the slowest work.** `QUICK_MODE` was read only to
  print a banner; no module honoured it. It now skips deep share enumeration
  (`hunt_sensitive_files`) and the per-host `spider_plus` content crawl.
- **Removed the misleading module-selection prompt.** `DO_ALL` was assigned but
  never read — answering "no" to "Run ALL checks?" still ran everything. Replaced
  with an honest status line; the final "Start enumeration?" prompt still aborts.
- **Trust SID-filtering / selective-auth parsing** rewritten to parse one LDIF
  entry at a time (sentinel-flushed, folding-aware), matching
  `analyze_trust_security`. The old `grep -A5 "trustPartner: $partner"` window
  mis-attributed attributes when entries shared values or attribute ordering
  differed.
- **`find` precedence** in the LOLBins startup-script scan: `-name` tests are now
  grouped with `\( … \)`, so `-type f` applies to all extensions (previously
  `*.cmd`/`*.ps1` directories could match).
- **Hashcat auto-crack** no longer assumes `/usr/share/wordlists/rockyou.txt`
  exists unzipped (it ships gzipped on a fresh Kali). A shared `resolve_wordlist`
  helper finds the list, honours `$ADENUM_WORDLIST`, and warns instead of
  launching hashcat against a missing file.

### Changed
- Counter increments standardised to `VAR=$((VAR+1))` across all modules (the
  `((VAR++))` form returns non-zero when the prior value was 0 — a latent
  `set -e` hazard the shared library already avoided).
- SARIF results now carry a synthetic `locations[]` so GitHub code scanning and
  strict SARIF consumers ingest them instead of rejecting location-less results.
- Added a real `tests/run_tests.sh` (syntax, byte-compile, the `_sq`
  command-injection guard, and a report_export round-trip) — the suite the
  Dockerfile and the v1.2.0 changelog already referenced.
- Removed dead code (`optional_tools`, `current_dn`).

## v1.2.0 — Capability upgrade

### Security
- **Command-injection hardening in generated commands.** BloodHound object
  names/SIDs are attacker-controlled; they were embedded into the bloodyAD /
  impacket command strings the tool generates without escaping. An object name
  containing a single quote could break out of the quoting and append arbitrary
  shell, so an operator pasting the generated command would run attacker-supplied
  shell on their own box. All embedded names are now shell-quoted via `_sq()`
  (verified by a test that an injected payload no longer executes).
- **LDAPS support + cleartext warning.** Added `--ldaps` / `ADENUM_LDAPS`; a
  plain LDAP simple bind sends the operator's password in cleartext, and the
  tool now warns when it does.
- **Removed `eval`** from the interactive prompt helpers (`printf -v` instead),
  so an entered value can never be interpreted as code.

### Added
- **Structured findings export.** Every finding is now also written to
  `findings.jsonl`, and a new `modules/report_export.py` produces
  `reports/findings.json`, `reports/findings.csv`, and `reports/findings.sarif`
  (SARIF 2.1.0 — drops straight into GitHub code scanning / SARIF viewers).
  Findings are enriched with a stable ID and a MITRE ATT&CK technique mapping.
- **Transitive BloodHound attack paths.** `bloodhound_parser.py` now builds a
  control graph (MemberOf + abusable ACE edges) and does BFS from the operator's
  SID to high-value targets (Domain/Enterprise/Schema Admins, Administrators,
  the domain object), emitting full multi-hop chains with per-edge BloodyAD
  steps — not just direct one-hop ACEs.
- **Dockerfile** with pinned Python tooling for reproducible runs.
- `LICENSE` (MIT), `.gitignore`, this changelog.

## v1.1.0 — Hardening

### Added
- `modules/00_common.sh` shared library: hardened `run_ldap` (quoted, RFC 2696
  paged results, clean stderr, real exit codes), RFC 2849 LDIF unfolding +
  base64-aware extraction, `recount_findings`, `make_uac_filter`, `to_int`.
- Non-interactive / automation mode: full CLI flags + `ADENUM_*` env vars +
  `--password -` (stdin); `--yes` for unattended runs.
- HTML report escaping for user-controlled fields.

### Fixed
- BloodHound parser resolved `PrincipalSID` (modern/CE format) — the
  auto-exploitation feature previously matched nothing; exact (non-substring)
  current-user matching; isolated/auto-cleaned temp dir; multi-label base DN;
  defensive guards against malformed exports.
- Kerberos hash counting (`grep -cF` for `$krb5tgs$`/`$krb5asrep$`).
- Trust analysis: per-entry parsing so attributes attach to the correct partner.
- Delegation: DC detection via `primaryGroupID` (516/521) instead of a name
  regex that both missed and mis-classified hosts.
- Report severity counts recomputed from the findings file (no more
  subshell-pipeline undercount); consistent `successful+failed <= total`.
- Credential exposure: live password no longer written into findings/reports.
- Per-module: `cd ... || return` (a failed `cd` no longer kills the run),
  PIPESTATUS exit-code capture, `grep -E` alternation, WMI namespace, removed
  duplicate module sourcing and the `$SECONDS` clobber, CLI value-flag guards.
