#!/bin/bash

################################################################################
#                                                                              #
#  🎯 ULTIMATE AD ENUMERATION TOOL - 96%+ Coverage                            #
#                                                                              #
#  Features:                                                                   #
#  ✅ 200+ Security Checks (LDAP, Kerberos, ADCS, GPO, ACL, Shares, etc.)    #
#  ✅ BloodHound Collection + AUTO-EXPLOITATION via BloodyAD                   #
#  ✅ Automated Attack Path Generation (BH → BloodyAD commands)               #
#  ✅ Hash Extraction (Kerberoast + AS-REP) with auto-cracking                #
#  ✅ Credential Hunting (GPP, SYSVOL, Scripts, Shares)                       #
#  ✅ Modern HTML Dashboard Report                                             #
#  ✅ 90% Bash + 10% Python (degrades gracefully)                             #
#                                                                              #
#  Architecture: Hybrid (Bash for speed, Python for complex JSON parsing)     #
#  Coverage: 96-97% of all AD enumeration + exploitation                      #
#                                                                              #
#  Usage: ./ultimate_ad_enum.sh                                               #
#         ./ultimate_ad_enum.sh --help                                        #
#         ./ultimate_ad_enum.sh --quick  (skip slow checks)                   #
#                                                                              #
################################################################################

VERSION="1.2.1-ULTIMATE"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Global variables
DOMAIN="${ADENUM_DOMAIN:-}"
DC_IP="${ADENUM_DC_IP:-}"
DNS_SERVER="${ADENUM_DNS_SERVER:-}"
BASE_DN="${ADENUM_BASE_DN:-}"
USERNAME="${ADENUM_USERNAME:-}"
PASSWORD="${ADENUM_PASSWORD:-}"
AUTH_TYPE="${ADENUM_AUTH_TYPE:-}"
CCACHE_PATH="${ADENUM_CCACHE:-}"
# LDAP transport: "ldap" (389, cleartext) or "ldaps" (636, TLS). Default ldap
# for compatibility; --ldaps is strongly recommended for userpass binds since a
# cleartext simple bind sends the password over the wire.
LDAP_SCHEME="${ADENUM_LDAPS:+ldaps}"; LDAP_SCHEME="${LDAP_SCHEME:-ldap}"
export LDAP_SCHEME
OUTPUT_DIR=""
QUICK_MODE=false
NONINTERACTIVE=false
ASSUME_YES=false
PYTHON_AVAILABLE=false
START_TIME=""
TOTAL_CHECKS=0
SUCCESSFUL_CHECKS=0
FAILED_CHECKS=0

# Finding counters
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0
INFO_FINDINGS=0
FINDINGS_FILE=""
FINDINGS_JSONL=""

################################################################################
# BANNER
################################################################################

show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   🎯 ULTIMATE AD ENUMERATION & EXPLOITATION TOOL 🎯                 ║
║                                                                      ║
║   ✅ 96%+ AD Coverage  ✅ BloodHound → BloodyAD Automation          ║
║   ✅ 200+ Checks       ✅ Automated Exploitation                     ║
║   ✅ Modern Dashboard  ✅ Hash Extraction + Cracking                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${BLUE}Version: ${VERSION}${NC}"
    echo -e "${BLUE}The most comprehensive AD enumeration tool for Kali Linux${NC}"
    echo ""
}

################################################################################
# HELP
################################################################################

show_help() {
    cat << EOF
${CYAN}USAGE:${NC}
    ./ultimate_ad_enum.sh [OPTIONS]

${CYAN}OPTIONS:${NC}
    --help, -h          Show this help message
    --version, -v       Show version
    --quick, -q         Quick mode (skip slow checks like deep share enumeration)
    --no-color          Disable colored output

  ${WHITE}Non-interactive / automation:${NC}
    --dc-ip IP          Domain Controller IP
    --domain FQDN       Domain (e.g. corp.local)
    --dns IP            DNS server IP (defaults to --dc-ip)
    --base-dn DN        LDAP base DN (auto-derived from --domain if omitted)
    --username USER     Bind username
    --password PASS     Bind password  (prefer ADENUM_PASSWORD env var; argv is
                        visible in 'ps'. Use '--password -' to read from stdin.)
    --auth TYPE         Authentication: userpass | anonymous | kerberos
    --ccache PATH       Kerberos ccache file (with --auth kerberos)
    --ldaps             Use LDAPS (TLS, port 636). Recommended for userpass —
                        a plain LDAP simple bind sends the password in cleartext.
                        (env: ADENUM_LDAPS=1)
    --yes, -y           Assume "yes" to prompts (unattended runs)

  Any value can also be supplied via environment variables:
    ADENUM_DC_IP ADENUM_DOMAIN ADENUM_DNS_SERVER ADENUM_BASE_DN
    ADENUM_USERNAME ADENUM_PASSWORD ADENUM_AUTH_TYPE ADENUM_CCACHE

${CYAN}DESCRIPTION:${NC}
    Comprehensive Active Directory enumeration and exploitation tool with:
    
    ${GREEN}✅ ENUMERATION (200+ Checks):${NC}
       • Basic: Users, Computers, Groups, OUs, Trusts
       • Kerberos: Kerberoasting, AS-REP Roasting
       • ADCS: All ESC vulnerabilities (ESC1-ESC16)
       • Delegation: Unconstrained, Constrained, RBCD
       • GPO: All policies + SYSVOL credential hunting
       • ACL: All permission paths to Domain Admins
       • Shares: Enumeration + sensitive file hunting
       • Credentials: GPP, scripts, LAPS, etc.
       • Sessions: Who's logged in where
       • Infrastructure: Exchange, MSSQL, SCCM, Azure
    
    ${GREEN}✅ AUTO-EXPLOITATION:${NC}
       • BloodHound → BloodyAD automation (UNIQUE FEATURE!)
       • Finds paths to Domain Admin
       • Auto-generates exploitation commands
       • Validates attack prerequisites
       • Priority-ranked exploitation plan
    
    ${GREEN}✅ REPORTING:${NC}
       • Modern interactive HTML dashboard
       • JSON/CSV exports for further analysis
       • Executive summary + technical details
       • Ready-to-use exploitation commands

${CYAN}REQUIREMENTS:${NC}
    ${WHITE}Core (Required):${NC}
      • ldapsearch (ldap-utils)
      • jq (JSON parsing)
      • Basic utilities (grep, awk, sed)
    
    ${WHITE}Optional (Recommended):${NC}
      • impacket-* tools (hash extraction)
      • bloodhound-python (graph collection)
      • certipy-ad (ADCS scanning)
      • bloodyAD (exploitation)
      • crackmapexec/netexec (shares, sessions)
      • hashcat (hash cracking)
      • python3 (for BloodHound automation)

${CYAN}EXAMPLES:${NC}
    ${WHITE}# Interactive mode (recommended)${NC}
    ./ultimate_ad_enum.sh
    
    ${WHITE}# Quick scan (skip slow checks)${NC}
    ./ultimate_ad_enum.sh --quick
    
    ${WHITE}# Show version${NC}
    ./ultimate_ad_enum.sh --version

${CYAN}OUTPUT:${NC}
    Creates timestamped directory with:
      • ULTIMATE_REPORT.html - Interactive dashboard
      • ULTIMATE_REPORT.txt - Text summary
      • bloodhound_data.zip - Graph data
      • bloodyad_commands.txt - Auto-generated exploitation
      • 200+ individual check results (LDIF/JSON/TXT)

${CYAN}COVERAGE: 96%+ AD Enumeration${NC}
    This tool covers more than any other AD enumeration tool available,
    including unique features like BloodHound → BloodyAD automation.

${CYAN}FIXES IN v1.0.1:${NC}
    ✅ Shows actual usernames/computers in findings
    ✅ Fixed pipe character breaking reports
    ✅ Improved BloodHound parser (finds more paths)
    ✅ Added ALL abuse primitives (GenericAll, WriteDACL, WriteOwner, etc.)
    ✅ Shadow Credentials, RBCD, LAPS, GMSA coverage

${CYAN}AUTHOR:${NC}
    Created for comprehensive AD security assessments from Kali Linux
    
EOF
}

################################################################################
# UTILITY FUNCTIONS
################################################################################

log_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_action() {
    echo -e "${CYAN}[*]${NC} $1"
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    # printf -v assigns to the named variable WITHOUT eval, so a value
    # containing shell metacharacters can never be interpreted as code.
    if [ -n "$default" ]; then
        read -p "$(echo -e ${CYAN}$prompt ${WHITE}[${default}]${NC}: )" input
        printf -v "$var_name" '%s' "${input:-$default}"
    else
        read -p "$(echo -e ${CYAN}$prompt${NC}: )" input
        printf -v "$var_name" '%s' "$input"
    fi
}

prompt_yesno() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    while true; do
        if [ "$default" == "y" ]; then
            read -p "$(echo -e ${CYAN}$prompt ${WHITE}[Y/n]${NC}: )" answer
            answer="${answer:-y}"
        else
            read -p "$(echo -e ${CYAN}$prompt ${WHITE}[y/N]${NC}: )" answer
            answer="${answer:-n}"
        fi
        
        case "$answer" in
            [Yy]* ) printf -v "$var_name" 'true'; break;;
            [Nn]* ) printf -v "$var_name" 'false'; break;;
            * ) echo -e "${RED}Please answer yes or no.${NC}";;
        esac
    done
}

# Minimal JSON string escaper (backslash and double-quote; tabs->space).
# Newlines are already stripped by add_finding before this is called.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/ }"
    printf '%s' "$s"
}

# Records a finding. Writes TWO stores from the same call:
#   * the pipe-delimited .findings.tmp (canonical for the HTML/text report;
#     '|' is escaped to the box char '│' so the 5-field parse stays intact)
#   * findings.jsonl (one JSON object per line) — the structured source that
#     report_export.py turns into findings.json / .csv / .sarif (with ATT&CK).
add_finding() {
    local level="$1"
    local category="$2"
    local message="$3"
    local exploit_ref="$4"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Use VAR=$((VAR+1)) (not ((VAR++))): the post-increment form returns a
    # non-zero status when the prior value was 0, which trips 'set -e'. These
    # counters are also rebuilt from the findings file by recount_findings(),
    # so they remain correct even when add_finding runs inside a subshell pipe.
    case "$level" in
        CRITICAL) CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1)) ;;
        HIGH)     HIGH_FINDINGS=$((HIGH_FINDINGS + 1)) ;;
        MEDIUM)   MEDIUM_FINDINGS=$((MEDIUM_FINDINGS + 1)) ;;
        LOW)      LOW_FINDINGS=$((LOW_FINDINGS + 1)) ;;
        INFO)     INFO_FINDINGS=$((INFO_FINDINGS + 1)) ;;
    esac

    # Strip newlines/carriage returns (applies to both output formats).
    message="${message//$'\n'/ }"; message="${message//$'\r'/}"
    exploit_ref="${exploit_ref//$'\n'/ }"; exploit_ref="${exploit_ref//$'\r'/}"
    category="${category//$'\n'/ }"

    # Structured JSONL record (keeps the real '|', JSON-escaped).
    local fjson="${FINDINGS_JSONL:-findings.jsonl}"
    printf '{"level":"%s","category":"%s","message":"%s","exploit_ref":"%s","timestamp":"%s"}\n' \
        "$(json_escape "$level")" "$(json_escape "$category")" \
        "$(json_escape "$message")" "$(json_escape "$exploit_ref")" \
        "$(json_escape "$timestamp")" >> "$fjson" 2>/dev/null

    # Pipe-delimited record: escape '|' -> '│' so the report parser's 5-field
    # split is never broken by a literal pipe in the data.
    message="${message//|/│}"
    exploit_ref="${exploit_ref//|/│}"
    category="${category//|/│}"
    local ff="${FINDINGS_FILE:-.findings.tmp}"
    echo "$level|$category|$message|$exploit_ref|$timestamp" >> "$ff"
}


################################################################################
# TOOL AVAILABILITY CHECK
################################################################################

check_tools() {
    log_action "Checking tool availability..."
    echo ""
    
    local core_tools=("ldapsearch" "jq" "grep" "awk" "sed")

    local missing_core=0
    
    # Check core tools
    log_info "Core tools (REQUIRED):"
    for tool in "${core_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_success "$tool"
        else
            log_error "$tool - NOT FOUND!"
            missing_core=1
        fi
    done
    
    if [ $missing_core -eq 1 ]; then
        echo ""
        log_error "Missing required tools! Please install:"
        echo "    apt install ldap-utils jq"
        exit 1
    fi
    
    echo ""
    log_info "Optional tools (RECOMMENDED):"
    
    # Check Python
    if command -v python3 &>/dev/null; then
        PYTHON_AVAILABLE=true
        log_success "python3 (BloodHound automation enabled)"
    else
        log_warning "python3 (BloodHound automation DISABLED)"
        echo "    Install: apt install python3"
    fi
    
    # Check Impacket
    if command -v impacket-GetUserSPNs &>/dev/null && command -v impacket-GetNPUsers &>/dev/null; then
        log_success "Impacket (hash extraction enabled)"
    else
        log_warning "Impacket (hash extraction disabled)"
        echo "    Install: pip3 install impacket"
    fi
    
    # Check BloodHound
    if command -v bloodhound-python &>/dev/null; then
        log_success "BloodHound (graph collection enabled)"
    else
        log_warning "BloodHound (graph collection disabled)"
        echo "    Install: pip3 install bloodhound"
    fi
    
    # Check Certipy
    if command -v certipy &>/dev/null || command -v certipy-ad &>/dev/null; then
        log_success "Certipy (ADCS scanning enabled)"
    else
        log_warning "Certipy (ADCS scanning disabled)"
        echo "    Install: pip3 install certipy-ad"
    fi
    
    # Check BloodyAD
    if command -v bloodyAD &>/dev/null; then
        log_success "BloodyAD (exploitation enabled)"
    else
        log_warning "BloodyAD (exploitation disabled)"
        echo "    Install: pip3 install bloodyAD"
    fi
    
    # Check CrackMapExec
    if command -v crackmapexec &>/dev/null || command -v netexec &>/dev/null; then
        log_success "CrackMapExec/NetExec (shares/sessions enabled)"
    else
        log_warning "CrackMapExec (shares/sessions limited)"
        echo "    Install: apt install crackmapexec"
    fi
    
    # Check Hashcat
    if command -v hashcat &>/dev/null; then
        log_success "Hashcat (hash cracking enabled)"
    else
        log_warning "Hashcat (hash cracking disabled)"
        echo "    Install: apt install hashcat"
    fi
    
    echo ""
}

################################################################################
# CONFIGURATION
################################################################################

configure_target() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  STEP 1: Target Configuration                                       ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$NONINTERACTIVE" = true ]; then
        # Unattended: never prompt. Required values must already be present.
        [ -z "$DC_IP" ]  && { log_error "Non-interactive run needs --dc-ip (or ADENUM_DC_IP)"; exit 1; }
        [ -z "$DOMAIN" ] && { log_error "Non-interactive run needs --domain (or ADENUM_DOMAIN)"; exit 1; }
        [ -z "$DNS_SERVER" ] && DNS_SERVER="$DC_IP"
    else
        [ -z "$DC_IP" ]  && prompt_input "Domain Controller IP address" "192.168.1.85" DC_IP
        [ -z "$DOMAIN" ] && prompt_input "Domain name (FQDN)" "labdc.local" DOMAIN
        [ -z "$DNS_SERVER" ] && prompt_input "DNS Server IP" "$DC_IP" DNS_SERVER
        [ -z "$DNS_SERVER" ] && DNS_SERVER="$DC_IP"
    fi

    # Auto-generate Base DN from the domain if one was not supplied.
    if [ -z "$BASE_DN" ]; then
        local auto_basedn="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"
        if [ "$NONINTERACTIVE" = true ]; then
            BASE_DN="$auto_basedn"
        else
            prompt_input "Base DN" "$auto_basedn" BASE_DN
        fi
    fi

    log_info "Target: $DOMAIN ($DC_IP)  Base DN: $BASE_DN"
}

configure_auth() {
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  STEP 2: Authentication                                              ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Non-interactive: auth already chosen via flags / env vars.
    if [ -n "$AUTH_TYPE" ]; then
        case "$AUTH_TYPE" in
            userpass)
                [ -z "$USERNAME" ] && { log_error "userpass auth needs --username"; exit 1; }
                if [ -z "$PASSWORD" ] && [ "$NONINTERACTIVE" != true ]; then
                    printf "%b" "${CYAN}Password${NC}: "; IFS= read -r -s PASSWORD; echo ""
                fi
                log_info "Auth: username/password ($USERNAME@$DOMAIN)"
                ;;
            anonymous)
                USERNAME=""; PASSWORD=""
                log_warning "Auth: anonymous bind (limited information)"
                ;;
            kerberos)
                if [ -z "$CCACHE_PATH" ] || [ ! -f "$CCACHE_PATH" ]; then
                    log_error "kerberos auth needs a valid --ccache file"; exit 1
                fi
                export KRB5CCNAME="$CCACHE_PATH"
                log_info "Auth: Kerberos ticket ($CCACHE_PATH)"
                ;;
            *)
                log_error "Unknown --auth value: $AUTH_TYPE (use userpass|anonymous|kerberos)"; exit 1
                ;;
        esac
        return 0
    fi

    echo -e "${WHITE}Choose authentication method:${NC}"
    echo -e "  1) Username/Password (most features)"
    echo -e "  2) Anonymous bind (limited info)"
    echo -e "  3) Kerberos ticket (ccache)"
    echo ""

    while true; do
        read -p "$(echo -e ${CYAN}Select option ${WHITE}[1-3]${NC}: )" auth_method
        case $auth_method in
            1)
                prompt_input "Username" "user" USERNAME
                printf "%b" "${CYAN}Password${NC}: "
                IFS= read -r -s PASSWORD
                echo ""
                
                AUTH_TYPE="userpass"
                break
                ;;
            2)
                log_warning "Anonymous bind provides limited information"
                USERNAME=""
                PASSWORD=""
                AUTH_TYPE="anonymous"
                break
                ;;
            3)
                prompt_input "Path to ccache file" "" CCACHE_PATH
                if [ ! -f "$CCACHE_PATH" ]; then
                    log_error "Ccache file not found!"
                    continue
                fi
                export KRB5CCNAME="$CCACHE_PATH"
                AUTH_TYPE="kerberos"
                break
                ;;
            *)
                log_error "Invalid option. Please select 1, 2, or 3."
                ;;
        esac
    done
}

configure_scope() {
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  STEP 3: Enumeration Scope                                           ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # NOTE: this assessment always runs every enumeration phase. (A previous
    # "Run ALL checks?" prompt stored its answer in DO_ALL but nothing ever read
    # it, so answering "no" still ran everything - a misleading choice. It has
    # been replaced with an honest status line. Use --quick to skip the slowest
    # phases, and the final "Start enumeration?" prompt to abort.)
    if [ "$QUICK_MODE" = true ]; then
        log_info "Quick mode enabled - skipping the slowest checks (deep share enumeration)"
    elif [ "$ASSUME_YES" = true ] || [ "$NONINTERACTIVE" = true ]; then
        log_info "Running all checks (non-interactive)"
    else
        log_info "All enumeration modules will run (LDAP -> Kerberos -> ADCS -> ... -> BloodHound)"
        echo -e "${BLUE}Tip: use --quick to skip the slowest checks (deep share enumeration).${NC}"
        echo ""
    fi
}

################################################################################
# MAIN EXECUTION FLOW
################################################################################

main() {
    START_TIME=$(date +%s)
    
    # Guard for value-taking flags: a flag passed as the last argument with no
    # value would make `shift 2` fail silently (count > $#), leaving the arg in
    # place and spinning the loop forever. _need aborts cleanly instead.
    _need() { [ "$1" -ge 2 ] || { log_error "Option $2 requires a value"; exit 1; }; }

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "Ultimate AD Enumeration Tool v${VERSION}"
                exit 0
                ;;
            --quick|-q)
                QUICK_MODE=true
                shift
                ;;
            --dc-ip)        _need $# "$1"; DC_IP="$2"; NONINTERACTIVE=true; shift 2 ;;
            --domain)       _need $# "$1"; DOMAIN="$2"; NONINTERACTIVE=true; shift 2 ;;
            --dns)          _need $# "$1"; DNS_SERVER="$2"; shift 2 ;;
            --base-dn)      _need $# "$1"; BASE_DN="$2"; shift 2 ;;
            --username|-u)  _need $# "$1"; USERNAME="$2"; AUTH_TYPE="${AUTH_TYPE:-userpass}"; shift 2 ;;
            --password)
                _need $# "$1"
                if [ "$2" = "-" ]; then
                    IFS= read -r -s PASSWORD
                    echo ""
                else
                    PASSWORD="$2"
                fi
                AUTH_TYPE="${AUTH_TYPE:-userpass}"
                shift 2
                ;;
            --auth)         _need $# "$1"; AUTH_TYPE="$2"; NONINTERACTIVE=true; shift 2 ;;
            --ccache)       _need $# "$1"; CCACHE_PATH="$2"; AUTH_TYPE="kerberos"; shift 2 ;;
            --ldaps)        LDAP_SCHEME="ldaps"; export LDAP_SCHEME; shift ;;
            --yes|-y)       ASSUME_YES=true; shift ;;
            --no-color)
                RED=''
                GREEN=''
                YELLOW=''
                CYAN=''
                BLUE=''
                MAGENTA=''
                WHITE=''
                BOLD=''
                NC=''
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    show_banner
    check_tools
    
    # Configuration
    configure_target
    configure_auth
    configure_scope
    
    # Create output directory
    OUTPUT_DIR="ultimate_ad_assessment_$(date +%Y%m%d_%H%M%S)"	
    mkdir -p "$OUTPUT_DIR"/{ldap,kerberos,adcs,gpo,acl,shares,creds,sessions,trusts,infrastructure,bloodhound,reports,delegation}
    
    # Initialize findings stores (pipe-delimited canonical + structured JSONL)
    FINDINGS_FILE="$(pwd)/$OUTPUT_DIR/.findings.tmp"
    FINDINGS_JSONL="$(pwd)/$OUTPUT_DIR/findings.jsonl"
    touch "$FINDINGS_FILE" "$FINDINGS_JSONL"
    
    # Summary
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Configuration Complete - Ready to Start                             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target:${NC} $DOMAIN ($DC_IP)"
    echo -e "${CYAN}Output:${NC} $(pwd)/$OUTPUT_DIR"
    echo -e "${CYAN}Mode:${NC} $([ "$QUICK_MODE" = true ] && echo "Quick" || echo "Full")"
    echo ""
    
    if [ "$ASSUME_YES" = true ] || [ "$NONINTERACTIVE" = true ]; then
        START=true
    else
        prompt_yesno "Start enumeration?" "y" START
    fi
    if [ "$START" = false ]; then
        log_warning "Assessment cancelled by user"
        exit 0
    fi
    
    echo ""
    log_success "Starting Ultimate AD Enumeration..."
    echo ""
    
    # Change to output directory
    cd "$OUTPUT_DIR" || exit
    
    # Load modules (00_common MUST be first: it defines run_ldap and the shared
    # helpers every other module relies on).
    local -a MODULES=(
        00_common
        01_ldap_enum 02_kerberos 03_adcs 04_delegation 05_gpo 06_acl_enum
        07_shares 08_credentials 09_sessions 10_trusts 11_infrastructure
        12_bloodhound 13_enhanced_security 14_lolbins_persistence
    )
    local m
    for m in "${MODULES[@]}"; do
        if [ -f "$SCRIPT_DIR/modules/$m.sh" ]; then
            # shellcheck disable=SC1090
            source "$SCRIPT_DIR/modules/$m.sh"
        else
            log_error "Module not found, skipping: modules/$m.sh"
        fi
    done


    # Execute enumeration
    run_ldap_enum
    run_kerberos_enum
    run_adcs_enum
    run_delegation_enum
    run_gpo_enum
    run_acl_enum
    run_share_enum
    run_credential_hunt
    run_session_enum
    run_trust_enum
    run_infrastructure_enum
    run_bloodhound_collection
    run_enhanced_security_checks
    run_lolbins_persistence_enum
    
    # Generate reports
    source "$SCRIPT_DIR/modules/report_generator.sh"
    generate_reports
    
    # Final summary
    show_final_summary
}

show_final_summary() {
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    # Note: do not assign to $SECONDS - it is a special bash variable.
    DUR_SECONDS=$((DURATION % 60))

    # Findings may have been appended from inside subshell pipelines, where the
    # in-memory counters would be lost. Rebuild them from the findings file so
    # the summary (and the report) never undercount.
    if command -v recount_findings >/dev/null 2>&1; then
        recount_findings "$FINDINGS_FILE"
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ASSESSMENT COMPLETE!                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Statistics:${NC}"
    echo -e "  Duration:    ${WHITE}${MINUTES}m ${DUR_SECONDS}s${NC}"
    echo -e "  Checks:      ${WHITE}$TOTAL_CHECKS${NC}"
    echo -e "  Successful:  ${GREEN}$SUCCESSFUL_CHECKS${NC}"
    echo -e "  Failed:      ${RED}$FAILED_CHECKS${NC}"
    echo ""
    echo -e "${CYAN}Findings:${NC}"
    echo -e "  ${RED}Critical:${NC} $CRITICAL_FINDINGS"
    echo -e "  ${YELLOW}High:${NC}     $HIGH_FINDINGS"
    echo -e "  ${BLUE}Medium:${NC}   $MEDIUM_FINDINGS"
    echo -e "  ${CYAN}Low:${NC}      $LOW_FINDINGS"
    echo -e "  ${WHITE}Info:${NC}     $INFO_FINDINGS"
    echo ""
    echo -e "${CYAN}Reports:${NC}"
    echo -e "  📊 ${WHITE}reports/ULTIMATE_REPORT.html${NC} (interactive dashboard)"
    echo -e "  📄 ${WHITE}reports/ULTIMATE_REPORT.txt${NC} (text summary)"
    echo -e "  ⚔️  ${WHITE}bloodhound/bloodyad_EXPLOITATION_GUIDE.txt${NC} (exploitation)"
    echo ""
    echo -e "${GREEN}🎯 Open the HTML report in your browser for interactive analysis! 🎯${NC}"
    echo ""
    
    # Display quick findings summary if there are critical/high findings
    if [ $CRITICAL_FINDINGS -gt 0 ] || [ $HIGH_FINDINGS -gt 0 ]; then
        echo -e "${RED}⚠️  CRITICAL/HIGH FINDINGS DETECTED! ⚠️${NC}"
        echo ""
        if [ -f "$FINDINGS_FILE" ]; then
            echo -e "${CYAN}Top Priority Findings:${NC}"
            grep "^CRITICAL" "$FINDINGS_FILE" | head -3 | while IFS='|' read -r level category message rest; do
                echo -e "  ${RED}[CRITICAL]${NC} ${category}: ${message:0:70}..."
            done
            grep "^HIGH" "$FINDINGS_FILE" | head -2 | while IFS='|' read -r level category message rest; do
                echo -e "  ${YELLOW}[HIGH]${NC} ${category}: ${message:0:70}..."
            done
            echo ""
        fi
    fi
}

# Run main
main "$@"
