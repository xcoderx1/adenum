🎯 Ultimate AD Enumeration & Exploitation Tool
96%+ Active Directory coverage · BloodHound → BloodyAD automation · Modern HTML report
This project is a modular, Kali-friendly AD assessment framework written mostly in Bash with a small amount of Python for BloodHound JSON parsing.
It’s designed to give you end-to-end coverage of a Windows AD environment:
✅ LDAP / Kerberos / ADCS / Delegation / GPO / ACL / Shares / Creds / Sessions / Trusts / Infra
✅ BloodHound collection and automated BloodyAD exploitation command generation
✅ Modern HTML dashboard + text report, with severity and category breakdown
✅ One-shot orchestration script: ultimate_ad_enum.sh
DISCLAIMER
This tool is for authorized security testing and lab use only.
Do not run this against networks you do not own or do not have explicit permission to test.
✨ Features
LDAP Enumeration (Phase 1)
Users, computers, groups, OUs, contacts
Privileged groups (Domain Admins, Enterprise Admins, Schema Admins, etc.)
Password policies, fine-grained password policies
Risky flags: adminCount=1, DONT_EXPIRE_PASSWORD, PASSWD_NOTREQD, reversible encryption, weak Kerberos crypto
Old OS detection (EOL systems), SIDHistory, test/temp accounts, credentials in description/info
Kerberos Attack Surface (Phase 2)
Kerberoastable accounts (servicePrincipalName)
AS-REP roastable accounts (no pre-auth)
Optional hash extraction with Impacket + optional hashcat cracking
ADCS (Phase 3)
Certipy-based enumeration of AD CS
Detection of ESC-style template issues (where supported)
Delegation (Phase 4)
Unconstrained delegation (computers + users)
Constrained delegation
Resource-Based Constrained Delegation (RBCD)
Trusted for delegation / trusted to authenticate
GPO, ACL, Shares, Creds, Sessions, Trusts, Infra (Phases 5–11)
GPO enumeration + links
ACL enumeration (mostly via BloodHound)
Share enumeration & credential hunting
Session enumeration (who is logged on where)
Domain/forest trusts
Exchange/MSSQL/SCCM/infra discovery
BloodHound + Auto-Exploitation (Phase 12)
bloodhound-python collection → ZIP
Python parser (bloodhound_parser.py) turns BH JSON into:
BloodyAD commands for practical abuse
Attack Path findings in the report
A human-readable exploitation guide (bloodyad_EXPLOITATION_GUIDE.txt)
Reporting
Interactive HTML dashboard: reports/ULTIMATE_REPORT.html
Text summary report: reports/ULTIMATE_REPORT.txt
Central findings file: .findings.tmp (all modules write here)
🧱 Project Structure
ultimate_ad_enum.sh        # Main orchestrator (entry point)
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
Each phase/module is called by ultimate_ad_enum.sh and writes both raw data and normalized findings.
🖥️ Requirements
OS
Linux (tested mainly on Kali)
Should also work on other Debian/Ubuntu-like systems with the same tools installed
Core tools (required)
These are mandatory; script will exit if they’re missing:
sudo apt update
sudo apt install -y \
  ldap-utils \   # ldapsearch
  jq \           # JSON parsing
  grep awk sed   # (usually already installed)
Optional tools (strongly recommended)
These unlock more functionality:
Python & BloodHound / ADCS / Exploitation
sudo apt install -y python3 python3-pip

# Impacket (Kerberoast / AS-REP roast):
sudo pip3 install impacket

# BloodHound collection:
sudo pip3 install bloodhound

# AD CS checks:
sudo pip3 install certipy-ad

# BloodyAD (ACL / path exploitation):
sudo pip3 install bloodyAD
Depending on your distro, some of these may also be available as packages
(e.g. python3-impacket, bloodhound-python in apt).
The script just checks for the executables in $PATH.
Other tools
CrackMapExec / NetExec – for shares/sessions, etc.
On Kali: sudo apt install crackmapexec (or install NetExec)
Hashcat – for cracking hashes (optional):
sudo apt install -y hashcat
The script will show you exactly what it found at runtime:
[✓] python3 (BloodHound automation enabled)
[✓] Impacket (hash extraction enabled)
[✓] BloodHound (graph collection enabled)
[✓] Certipy (ADCS scanning enabled)
[✓] BloodyAD (exploitation enabled)
[✓] CrackMapExec/NetExec (shares/sessions enabled)
[✓] Hashcat (hash cracking enabled)
📦 Installation
git clone https://github.com/YOUR_USER/YOUR_REPO.git
cd YOUR_REPO

# Make the main script and modules executable
chmod +x ultimate_ad_enum.sh
chmod +x modules/*.sh
(Replace YOUR_USER/YOUR_REPO with your own repo path.)
🚀 Usage
1. Interactive mode (recommended to start)
sudo ./ultimate_ad_enum.sh
The tool will:
Show a banner and tool check
Ask for:
Domain controller IP
Domain (FQDN)
DNS server
Base DN (e.g. DC=labdc,DC=local)
Ask for authentication method:
Username/password
Anonymous
Kerberos ticket (ccache)
Ask which modules to run (or “ALL”)
Run each phase in order:
LDAP → Kerberos → ADCS → … → BloodHound
Generate reports at the end
2. Example: quick run with username/password
Exact flags may evolve; always check ./ultimate_ad_enum.sh --help for up-to-date usage.
sudo ./ultimate_ad_enum.sh \
  --domain labdc.local \
  --dc-ip 192.168.1.217 \
  --dns 192.168.1.217 \
  --base-dn "DC=labdc,DC=local" \
  --username pentest \
  --password 'SuperSecret123!' \
  --quick
Common flags:
--domain – AD DNS name
--dc-ip – domain controller IP
--dns – DNS server (often same as DC)
--base-dn – LDAP base DN
--username / --password – credentials
--quick – quick mode (skips some slower/noisier checks)
See:
./ultimate_ad_enum.sh --help
for more options (e.g. --no-color, --version).
📁 Output Structure
Each run creates a timestamped directory:
ultimate_ad_assessment_YYYYMMDD_HHMMSS/
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
Open the HTML report with your browser (on Kali, for example):
firefox reports/ULTIMATE_REPORT.html &
🧪 Troubleshooting
No findings in HTML?
Check .findings.tmp inside the assessment folder:
cat ultimate_ad_assessment_*/.findings.tmp | head
If it’s empty, some module may not have run or LDAP auth failed.
BloodHound auto-exploitation skipped
Check:
python3 is installed and in $PATH
modules/bloodhound_parser.py exists
Then look at:
cat bloodhound/bloodyad_automation.log
ADCS scan errors
Certipy is noisy when ADCS is unreachable; this does not break the rest of the tool.
Review adcs/ directory for details.
🤝 Contributing
PRs and issues are welcome.
Found a missing attack surface?
Want to add a new module?
Found a bug in reporting or BloodHound parsing?
Open an issue or PR with:
Repro steps
Expected vs actual behaviour
Logs/snippets if possible
⚠️ Legal Notice
This tool is provided as is, without any warranty.
The author(s) are not responsible for any misuse or damage caused by this software.
Use responsibly. Only test environments you’re explicitly allowed to. 🛡️
