<h1>🎯 Ultimate AD Enumeration &amp; Exploitation Tool</h1>

<p><strong>96%+ Active Directory coverage · BloodHound → BloodyAD automation · Modern HTML report</strong></p>

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
  01_ldap_enum.sh          # LDAP enumeration
  02_kerberos.sh           # Kerberos attacks (Kerberoast / AS-REP)
  03_adcs.sh               # AD CS checks via Certipy
  04_delegation.sh         # Delegation / RBCD
  05_gpo.sh                # GPO enumeration
  06_acl_enum.sh           # ACL enumeration (BloodHound-focused)
  07_shares.sh             # Share enumeration
  08_credentials.sh        # Credential hunting
  09_sessions.sh           # Session enumeration
  10_trusts.sh             # Trust relationships
  11_infrastructure.sh     # Infra discovery (MSSQL, Exchange, etc.)
  12_bloodhound.sh         # BloodHound + BloodyAD auto-exploitation
  bloodhound_parser.py     # BloodHound JSON → BloodyAD commands
  report_generator.sh      # HTML + text report generation
</code></pre>

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
