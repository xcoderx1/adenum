<h1>🎯 Ultimate AD Enumeration &amp; Exploitation Tool</h1>

<p><strong>Active Directory coverage · BloodHound → BloodyAD automation · Modern HTML report</strong></p>

<p>
  This project is a <strong>modular, Kali-friendly AD assessment framework</strong> written mostly in Bash
  with a small amount of Python for BloodHound JSON parsing.
</p>

<p>It’s designed to give you <strong>end-to-end coverage</strong> of a Windows AD environment:</p>

<ul>
  <li>✅ LDAP / Kerberos / ADCS / Delegation / GPO / ACL / Shares / Creds / Sessions / Trusts / Infra</li>
  <li>✅ BloodHound collection <strong>and</strong> automated BloodyAD exploitation command generation</li>
  <li>✅ Modern HTML dashboard + text report, with severity and category breakdown</li>
  <li>✅ One-shot orchestrator script: <code>ultimate_ad_enum.sh</code></li>
</ul>

<p style="background:#451a03;padding:0.75rem 1rem;border-left:4px solid #f97316;border-radius:4px;">
  <strong>DISCLAIMER</strong><br/>
  This tool is for <strong>authorized security testing and lab use only</strong>.<br/>
  Do <strong>not</strong> run this against networks you do not own or do not have explicit permission to test.
</p>

<hr />

<h2>🆕 What's new in v1.2.0 (capabilities)</h2>

<ul>
  <li><strong>Structured findings export.</strong> Alongside the HTML/text report, every run now
      writes <code>findings.jsonl</code> and (via <code>modules/report_export.py</code>)
      <code>reports/findings.json</code>, <code>reports/findings.csv</code>, and
      <code>reports/findings.sarif</code> (SARIF 2.1.0 — imports into GitHub code scanning / SARIF
      viewers). Findings carry a stable ID and a MITRE ATT&amp;CK technique mapping.</li>
  <li><strong>Transitive BloodHound attack paths.</strong> The parser now builds a control graph
      (MemberOf + abusable ACE edges) and does BFS from your SID to high-value targets (Domain /
      Enterprise / Schema Admins, Administrators, the domain object), emitting full
      <strong>multi-hop</strong> chains with per-edge BloodyAD steps — not just direct one-hop ACEs.</li>
  <li><strong>Docker.</strong> A pinned <code>Dockerfile</code> gives a reproducible runtime.</li>
</ul>

<h3>Run via Docker</h3>
<pre><code>docker build -t adenum .
docker run --rm -it adenum --dc-ip 10.0.0.10 --domain corp.local \
  --username jdoe --password - --yes
</code></pre>

<hr />

<h2>🆕 What's new in v1.1.0 (hardening release)</h2>

<ul>
  <li><strong>Shared library (<code>modules/00_common.sh</code>)</strong> — a single hardened
      <code>run_ldap</code> plus robust LDIF helpers used by every module.</li>
  <li><strong>LDAP paged results (RFC&nbsp;2696)</strong> — searches no longer silently truncate at
      the server's <code>MaxPageSize</code> (~1000 entries), so large/enterprise domains enumerate fully.</li>
  <li><strong>Robust LDIF parsing</strong> — RFC&nbsp;2849 line-folding and base64
      (<code>attr:: …</code>) values are handled, so wrapped/encoded names are no longer lost.</li>
  <li><strong>Accurate report counts</strong> — severity totals are recomputed from the findings file,
      fixing under-counting when findings were generated inside shell pipelines.</li>
  <li><strong>No credential leakage</strong> — the live password is never written into a finding or the
      HTML/text report; passwords can be supplied via env var or stdin instead of <code>argv</code>.</li>
  <li><strong>Non-interactive / automation mode</strong> — full CLI flags and environment variables for
      unattended runs (see Usage).</li>
  <li><strong>BloodHound parser fixes</strong> — resolves <code>PrincipalSID</code> (modern BloodHound /
      CE format), exact (non-substring) current-user matching, isolated &amp; auto-cleaned temp dir, and
      correct base-DN derivation for any number of domain labels.</li>
  <li><strong>Per-module bug fixes</strong> — correct exit-code capture after pipes
      (<code>PIPESTATUS</code>), ESC1↔ESC16 word-boundary matching, fixed grep alternation, safe
      <code>cd&nbsp;||&nbsp;return</code> (a failed <code>cd</code> no longer kills the whole run),
      HTML-escaped report headers, and fleshed-out infrastructure / session / credential modules.</li>
</ul>

<hr />

<h2>✨ Features</h2>

<h3>LDAP Enumeration (Phase 1)</h3>
<ul>
  <li>Users, computers, groups, OUs, contacts</li>
  <li>Privileged groups (Domain Admins, Enterprise Admins, Schema Admins, etc.)</li>
  <li>Password policies, fine-grained password policies</li>
  <li>
    Risky flags: <code>adminCount=1</code>, <code>DONT_EXPIRE_PASSWORD</code>,
    <code>PASSWD_NOTREQD</code>, reversible encryption, weak Kerberos crypto
  </li>
  <li>Old OS detection (EOL systems), SIDHistory, test/temp accounts</li>
  <li>Credentials in user description / info fields</li>
</ul>

<h3>Kerberos Attack Surface (Phase 2)</h3>
<ul>
  <li>Kerberoastable accounts (<code>servicePrincipalName</code>)</li>
  <li>AS-REP roastable accounts (no pre-auth)</li>
  <li>Optional hash extraction with Impacket + optional hashcat cracking</li>
</ul>

<h3>ADCS (Phase 3)</h3>
<ul>
  <li>Certipy-based enumeration of AD CS</li>
  <li>Detection of ESC-style template issues (where supported)</li>
</ul>

<h3>Delegation (Phase 4)</h3>
<ul>
  <li>Unconstrained delegation (computers + users)</li>
  <li>Constrained delegation</li>
  <li>Resource-Based Constrained Delegation (RBCD)</li>
  <li>Accounts trusted for delegation / trusted to authenticate</li>
</ul>

<h3>GPO, ACL, Shares, Creds, Sessions, Trusts, Infra (Phases 5–11)</h3>
<ul>
  <li>GPO enumeration + links</li>
  <li>ACL enumeration (mostly via BloodHound)</li>
  <li>Share enumeration &amp; credential hunting</li>
  <li>Session enumeration (who is logged on where)</li>
  <li>Domain/forest trusts</li>
  <li>Exchange / MSSQL / SCCM / other infra discovery</li>
</ul>

<h3>BloodHound + Auto-Exploitation (Phase 12)</h3>
<ul>
  <li><code>bloodhound-python</code> collection → ZIP</li>
  <li>
    Python parser (<code>bloodhound_parser.py</code>) turns BH JSON into:
    <ul>
      <li><strong>BloodyAD commands</strong> for practical abuse</li>
      <li><strong>Attack Path findings</strong> in the report</li>
      <li>Human-readable exploitation guide: <code>bloodyad_EXPLOITATION_GUIDE.txt</code></li>
    </ul>
  </li>
</ul>

<h3>Reporting</h3>
<ul>
  <li>Interactive HTML dashboard: <code>reports/ULTIMATE_REPORT.html</code></li>
  <li>Text summary report: <code>reports/ULTIMATE_REPORT.txt</code></li>
  <li>Central findings file: <code>.findings.tmp</code> (all modules write here)</li>
</ul>

<hr />

<h2>🧱 Project Structure</h2>

<pre><code>ultimate_ad_enum.sh        # Main orchestrator (entry point)
modules/
  00_common.sh             # Shared library: hardened run_ldap + LDIF helpers
  01_ldap_enum.sh          # LDAP enumeration
  02_kerberos.sh           # Kerberos attacks (Kerberoast / AS-REP)
  03_adcs.sh               # AD CS checks via Certipy (ESC1-ESC16)
  04_delegation.sh         # Delegation / RBCD
  05_gpo.sh                # GPO enumeration + SYSVOL/GPP hunting
  06_acl_enum.sh           # ACL enumeration (BloodHound-focused)
  07_shares.sh             # Share enumeration
  08_credentials.sh        # Credential-bearing attribute hunting
  09_sessions.sh           # Session enumeration
  10_trusts.sh             # Trust relationships
  11_infrastructure.sh     # Infra discovery (MSSQL, Exchange, SCCM, ADFS)
  12_bloodhound.sh         # BloodHound + BloodyAD auto-exploitation
  13_enhanced_security.sh  # Extra hygiene/security checks
  14_lolbins_persistence.sh# LOLBins & persistence-mechanism checks
  bloodhound_parser.py     # BloodHound JSON → BloodyAD commands
  report_generator.sh      # HTML + text report generation
  report_export.py         # findings.jsonl → JSON / CSV / SARIF (+ ATT&CK)

# Standalone companion scripts (not invoked by the orchestrator):
adpow.txt                  # PowerShell 5.1 AD audit script — run FROM a
                           # domain-joined Windows host (rename to .ps1 to use)
domainfinder.txt           # One-liner: find the DC via DNS SRV records
</code></pre>

<h3>Companion scripts</h3>
<ul>
  <li><code>adpow.txt</code> — a self-contained <strong>PowerShell</strong> AD enumeration/audit
      script (PS 5.1). It is an <em>alternative</em> to the Bash toolkit for when you are running on a
      domain-joined Windows box rather than from Kali. It is not called by <code>ultimate_ad_enum.sh</code>.
      Rename to <code>.ps1</code> and run, e.g.:
      <code>powershell -ep bypass -File .\adpow.ps1 -Domain corp.local -DcIP 10.0.0.10</code>.</li>
  <li><code>domainfinder.txt</code> — a small DNS helper to discover the Domain Controller via the
      <code>_ldap._tcp.dc._msdcs</code> SRV record when you only know the domain name.</li>
</ul>

<p>
  Each phase/module is called by <code>ultimate_ad_enum.sh</code> and writes both raw data and
  normalized findings.
</p>

<hr />

<h2>🖥️ Requirements</h2>

<h3>OS</h3>
<ul>
  <li>Linux (tested mainly on <strong>Kali</strong>)</li>
  <li>Other Debian/Ubuntu-like systems with the same tools installed should also work</li>
</ul>

<h3>Core tools (required)</h3>

<p>These are <strong>mandatory</strong>; the script will exit if they’re missing:</p>

<pre><code>sudo apt update
sudo apt install -y \
  ldap-utils \   # ldapsearch
  jq \           # JSON parsing
  grep awk sed   # (usually already installed)
</code></pre>

<h3>Optional tools (strongly recommended)</h3>

<p>These unlock more functionality.</p>

<h4>Python &amp; BloodHound / ADCS / Exploitation</h4>

<pre><code>sudo apt install -y python3 python3-pip

# Impacket (Kerberoast / AS-REP roast):
sudo pip3 install impacket

# BloodHound collection:
sudo pip3 install bloodhound

# AD CS checks:
sudo pip3 install certipy-ad

# BloodyAD (ACL / path exploitation):
sudo pip3 install bloodyAD
</code></pre>

<p>
  Depending on your distro, some may also be available as packages
  (e.g. <code>python3-impacket</code>, <code>bloodhound-python</code> in apt).
  The script just checks for the <strong>executables</strong> in <code>$PATH</code>.
</p>

<h4>Other tools</h4>

<ul>
  <li><strong>CrackMapExec / NetExec</strong> – for shares/sessions, etc.</li>
  <li><strong>Hashcat</strong> – for cracking hashes (optional):</li>
</ul>

<pre><code>sudo apt install -y crackmapexec hashcat
</code></pre>

<hr />

<h2>📦 Installation</h2>

<pre><code>git clone https://github.com/YOUR_USER/YOUR_REPO.git
cd YOUR_REPO

# Make the main script and modules executable
chmod +x ultimate_ad_enum.sh
chmod +x modules/*.sh
</code></pre>

<p>(Replace <code>YOUR_USER/YOUR_REPO</code> with your own repo path.)</p>

<hr />

<h2>🚀 Usage</h2>

<h3>Interactive mode (recommended to start)</h3>

<pre><code>sudo ./ultimate_ad_enum.sh
</code></pre>

<p>The tool will:</p>

<ol>
  <li>Show a banner and tool check</li>
  <li>Ask for domain controller IP, domain (FQDN), DNS server, base DN</li>
  <li>Ask for authentication method (user/pass, anonymous, or Kerberos ticket)</li>
  <li>Ask which modules to run (or ALL)</li>
  <li>Run LDAP → Kerberos → ADCS → … → BloodHound</li>
  <li>Generate reports at the end</li>
</ol>

<h3>Non-interactive / automation mode</h3>

<p>Supply everything on the command line (or via environment variables) and add
<code>--yes</code> for a fully unattended run:</p>

<pre><code># Username / password
sudo ./ultimate_ad_enum.sh \
  --dc-ip 10.0.0.10 --domain corp.local \
  --username jdoe --password 'P@ssw0rd!' --auth userpass --yes

# Read the password from stdin (keeps it out of 'ps' / shell history)
echo 'P@ssw0rd!' | sudo ./ultimate_ad_enum.sh \
  --dc-ip 10.0.0.10 --domain corp.local --username jdoe --password - --yes

# Or via environment variables (also keeps the password off argv)
ADENUM_PASSWORD='P@ssw0rd!' sudo -E ./ultimate_ad_enum.sh \
  --dc-ip 10.0.0.10 --domain corp.local --username jdoe --auth userpass --yes

# Anonymous bind, Kerberos ticket
sudo ./ultimate_ad_enum.sh --dc-ip 10.0.0.10 --domain corp.local --auth anonymous --yes
sudo ./ultimate_ad_enum.sh --dc-ip 10.0.0.10 --domain corp.local --auth kerberos --ccache /tmp/jdoe.ccache --yes
</code></pre>

<p>Run <code>./ultimate_ad_enum.sh --help</code> for the full flag and environment-variable list.</p>

<hr />

<h2>📁 Output Structure</h2>

<pre><code>ultimate_ad_assessment_YYYYMMDD_HHMMSS/
  .findings.tmp                 # Master findings (all modules)
  ldap/                         # LDAP LDIFs
  kerberos/                     # Kerberos outputs, hashes (if any)
  adcs/                         # Certipy outputs
  delegation/                   # Delegation LDIFs
  gpo/                          # GPO enumeration
  acl/                          # ACL / permissions info
  shares/                       # Share enumeration
  creds/                        # Credential hunting results
  sessions/                     # Session data
  trusts/                       # Trust relationships
  infrastructure/               # Infra discovery
  bloodhound/
    YYYYMMDDHHMMSS_bloodhound.zip    # BloodHound data
    bloodyad_automation.json         # Parsed BH → BloodyAD data (if paths found)
    bloodyad_commands.txt            # Raw BloodyAD commands (if paths found)
    bloodyad_EXPLOITATION_GUIDE.txt  # Human-readable exploit guide
    bloodhound_cypher_queries.txt    # Handy Cypher queries for BH GUI
  reports/
    ULTIMATE_REPORT.html        # Interactive HTML dashboard
    ULTIMATE_REPORT.txt         # Text summary
</code></pre>

<hr />

<h2>⚠️ Legal Notice</h2>

<p>
  This tool is provided <strong>as is</strong>, without any warranty.<br/>
  The author(s) are <strong>not responsible</strong> for any misuse or damage caused by this software.
</p>

<p>Use responsibly. Only test environments you’re explicitly allowed to. 🛡️</p>
