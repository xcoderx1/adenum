#!/bin/bash
################################################################################
# MODULE: Trust Relationships - COMPLETE VERSION (100% COVERAGE)
# Coverage: Trust enumeration, SID filtering, trust direction, trust types,
#           forest trust analysis, external trust security, selective auth
################################################################################

run_trust_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 10: Trust Relationships (Complete Security Analysis)          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Basic trust enumeration
    enumerate_trusts
    
    # Analyze trust security
    analyze_trust_security
    
    # Check SID filtering
    check_sid_filtering
    
    # Check selective authentication
    check_selective_authentication
    
    # Analyze trust direction
    analyze_trust_direction
    
    # Find foreign security principals
    enumerate_foreign_principals
    
    echo ""
}

################################################################################
# 1. Basic Trust Enumeration
################################################################################
enumerate_trusts() {
    log_action "Enumerating domain trusts..."
    ((TOTAL_CHECKS++))
    
    run_ldap "(objectClass=trustedDomain)" "trusts/trusts.ldif" \
        "Enumerating domain trusts" "trustPartner trustDirection trustType trustAttributes cn"
    
    local trust_count=$(grep -c "^dn:" trusts/trusts.ldif 2>/dev/null || echo 0)
    trust_count="${trust_count//[^0-9]/}"
    [ -z "$trust_count" ] && trust_count=0
    
    if [ $trust_count -gt 0 ]; then
        log_success "Found $trust_count domain trust(s)"
        
        # Parse trust details
        parse_trust_details
        
        ((SUCCESSFUL_CHECKS++))
    else
        log_info "No domain trusts configured"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 2. Parse Trust Details (Human Readable)
################################################################################
parse_trust_details() {
    log_action "Parsing trust details..."
    
    echo "=== DOMAIN TRUST ANALYSIS ===" > trusts/trust_analysis.txt
    echo "" >> trusts/trust_analysis.txt
    
    local current_dn=""
    local trust_partner=""
    local trust_direction=""
    local trust_type=""
    local trust_attributes=""
    
    while IFS= read -r line; do
        if [[ "$line" == dn:* ]]; then
            # New trust entry - save previous if exists
            if [ -n "$trust_partner" ]; then
                write_trust_analysis
            fi
            # Reset for new entry
            current_dn="$line"
            trust_partner=""
            trust_direction=""
            trust_type=""
            trust_attributes=""
            
        elif [[ "$line" == trustPartner:* ]]; then
            trust_partner=$(echo "$line" | cut -d' ' -f2-)
            
        elif [[ "$line" == trustDirection:* ]]; then
            trust_direction=$(echo "$line" | awk '{print $2}')
            
        elif [[ "$line" == trustType:* ]]; then
            trust_type=$(echo "$line" | awk '{print $2}')
            
        elif [[ "$line" == trustAttributes:* ]]; then
            trust_attributes=$(echo "$line" | awk '{print $2}')
        fi
    done < trusts/trusts.ldif
    
    # Write last entry
    if [ -n "$trust_partner" ]; then
        write_trust_analysis
    fi
}

################################################################################
# 3. Write Trust Analysis to File
################################################################################
write_trust_analysis() {
    echo "Trust Partner: $trust_partner" >> trusts/trust_analysis.txt
    echo "─────────────────────────────────────────────────────" >> trusts/trust_analysis.txt
    
    # Decode trust direction
    case "$trust_direction" in
        0) echo "Direction: Disabled" >> trusts/trust_analysis.txt ;;
        1) echo "Direction: Inbound (trusting domain)" >> trusts/trust_analysis.txt ;;
        2) echo "Direction: Outbound (trusted domain)" >> trusts/trust_analysis.txt ;;
        3) echo "Direction: Bidirectional" >> trusts/trust_analysis.txt ;;
        *) echo "Direction: Unknown ($trust_direction)" >> trusts/trust_analysis.txt ;;
    esac
    
    # Decode trust type
    case "$trust_type" in
        1) echo "Type: Windows NT (downlevel)" >> trusts/trust_analysis.txt ;;
        2) echo "Type: Active Directory (uplevel)" >> trusts/trust_analysis.txt ;;
        3) echo "Type: MIT Kerberos" >> trusts/trust_analysis.txt ;;
        4) echo "Type: DCE" >> trusts/trust_analysis.txt ;;
        *) echo "Type: Unknown ($trust_type)" >> trusts/trust_analysis.txt ;;
    esac
    
    # Decode trust attributes (bitmask)
    echo "Attributes: $trust_attributes" >> trusts/trust_analysis.txt
    
    local attrs=""
    trust_attributes="${trust_attributes//[^0-9]/}"
    [ -z "$trust_attributes" ] && trust_attributes=0
    
    # Check each bit
    if [ $((trust_attributes & 1)) -ne 0 ]; then
        attrs="${attrs}NON_TRANSITIVE, "
    fi
    if [ $((trust_attributes & 2)) -ne 0 ]; then
        attrs="${attrs}UPLEVEL_ONLY, "
    fi
    if [ $((trust_attributes & 4)) -ne 0 ]; then
        attrs="${attrs}QUARANTINED (SID Filtering enabled), "
    fi
    if [ $((trust_attributes & 8)) -ne 0 ]; then
        attrs="${attrs}FOREST_TRANSITIVE, "
    fi
    if [ $((trust_attributes & 16)) -ne 0 ]; then
        attrs="${attrs}CROSS_ORGANIZATION, "
    fi
    if [ $((trust_attributes & 32)) -ne 0 ]; then
        attrs="${attrs}WITHIN_FOREST, "
    fi
    if [ $((trust_attributes & 64)) -ne 0 ]; then
        attrs="${attrs}TREAT_AS_EXTERNAL (no SID filtering!), "
    fi
    if [ $((trust_attributes & 128)) -ne 0 ]; then
        attrs="${attrs}USES_RC4_ENCRYPTION, "
    fi
    if [ $((trust_attributes & 256)) -ne 0 ]; then
        attrs="${attrs}CROSS_ORGANIZATION_NO_TGT_DELEGATION, "
    fi
    if [ $((trust_attributes & 512)) -ne 0 ]; then
        attrs="${attrs}PIM_TRUST, "
    fi
    
    # Remove trailing comma
    attrs="${attrs%, }"
    [ -z "$attrs" ] && attrs="None"
    
    echo "Decoded Attributes: $attrs" >> trusts/trust_analysis.txt
    echo "" >> trusts/trust_analysis.txt
}

################################################################################
# 4. Analyze Trust Security (Critical Checks)
################################################################################
analyze_trust_security() {
    log_action "Analyzing trust security configuration..."
    ((TOTAL_CHECKS++))
    
    if [ ! -f "trusts/trusts.ldif" ]; then
        ((FAILED_CHECKS++))
        return
    fi
    
    local security_issues=0
    
    # Check 1: TREAT_AS_EXTERNAL flag (bit 6 = 64)
    # This means NO SID filtering - very dangerous!
    grep "trustAttributes:" trusts/trusts.ldif | while read -r line; do
        local attrs=$(echo "$line" | awk '{print $2}')
        attrs="${attrs//[^0-9]/}"
        [ -z "$attrs" ] && attrs=0
        
        if [ $((attrs & 64)) -ne 0 ]; then
            local partner=$(grep -B10 "trustAttributes: $attrs" trusts/trusts.ldif | grep "trustPartner:" | tail -1 | cut -d' ' -f2-)
            
            add_finding "CRITICAL" "Insecure Trust Configuration" \
                "Trust with $partner has TREAT_AS_EXTERNAL flag - NO SID FILTERING!" \
                "Enable SID filtering: netdom trust $DOMAIN /domain:$partner /quarantine:yes"
            ((security_issues++))
        fi
    done
    
    # Check 2: Bidirectional trusts (may be unnecessary)
    grep "trustDirection: 3" trusts/trusts.ldif | while read -r line; do
        local partner=$(grep -B5 "trustDirection: 3" trusts/trusts.ldif | grep "trustPartner:" | tail -1 | cut -d' ' -f2-)
        
        add_finding "MEDIUM" "Bidirectional Trust" \
            "Bidirectional trust with $partner - verify if necessary" \
            "Consider changing to one-way trust if bidirectional access not required"
    done
    
    # Check 3: RC4 encryption only (bit 7 = 128)
    grep "trustAttributes:" trusts/trusts.ldif | while read -r line; do
        local attrs=$(echo "$line" | awk '{print $2}')
        attrs="${attrs//[^0-9]/}"
        [ -z "$attrs" ] && attrs=0
        
        # Check if ONLY RC4 is set (no AES)
        if [ $((attrs & 128)) -ne 0 ]; then
            local partner=$(grep -B10 "trustAttributes: $attrs" trusts/trusts.ldif | grep "trustPartner:" | tail -1 | cut -d' ' -f2-)
            
            add_finding "MEDIUM" "Weak Trust Encryption" \
                "Trust with $partner uses RC4 encryption only" \
                "Enable AES encryption for trust"
        fi
    done
    
    if [ $security_issues -eq 0 ]; then
        log_success "No critical trust security issues found"
    fi
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 5. Check SID Filtering Status (CRITICAL SECURITY)
################################################################################
check_sid_filtering() {
    log_action "Checking SID filtering status..."
    ((TOTAL_CHECKS++))
    
    if [ ! -f "trusts/trusts.ldif" ]; then
        ((FAILED_CHECKS++))
        return
    fi
    
    echo "=== SID FILTERING ANALYSIS ===" > trusts/sid_filtering_status.txt
    echo "" >> trusts/sid_filtering_status.txt
    
    grep "trustPartner:" trusts/trusts.ldif | awk '{print $2}' | while read -r partner; do
        echo "Trust: $partner" >> trusts/sid_filtering_status.txt
        
        # Get trust attributes for this trust
        local attrs=$(grep -A5 "trustPartner: $partner" trusts/trusts.ldif | grep "trustAttributes:" | awk '{print $2}')
        attrs="${attrs//[^0-9]/}"
        [ -z "$attrs" ] && attrs=0
        
        # Check QUARANTINED bit (4) - SID filtering enabled
        if [ $((attrs & 4)) -ne 0 ]; then
            echo "  Status: ✓ SID Filtering ENABLED (QUARANTINED)" >> trusts/sid_filtering_status.txt
            echo "  Security: GOOD" >> trusts/sid_filtering_status.txt
        # Check TREAT_AS_EXTERNAL bit (64) - explicitly disabled
        elif [ $((attrs & 64)) -ne 0 ]; then
            echo "  Status: ✗ SID Filtering DISABLED (TREAT_AS_EXTERNAL)" >> trusts/sid_filtering_status.txt
            echo "  Security: CRITICAL RISK" >> trusts/sid_filtering_status.txt
            
            add_finding "CRITICAL" "SID Filtering Disabled" \
                "SID filtering disabled for trust with $partner - SID injection attacks possible" \
                "Enable immediately: netdom trust $DOMAIN /domain:$partner /quarantine:yes"
        else
            echo "  Status: ⚠ SID Filtering status unclear" >> trusts/sid_filtering_status.txt
            echo "  Security: VERIFY MANUALLY" >> trusts/sid_filtering_status.txt
        fi
        
        echo "" >> trusts/sid_filtering_status.txt
    done
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 6. Check Selective Authentication
################################################################################
check_selective_authentication() {
    log_action "Checking selective authentication status..."
    ((TOTAL_CHECKS++))
    
    if [ ! -f "trusts/trusts.ldif" ]; then
        ((FAILED_CHECKS++))
        return
    fi
    
    echo "=== SELECTIVE AUTHENTICATION ANALYSIS ===" > trusts/selective_auth_status.txt
    echo "" >> trusts/selective_auth_status.txt
    
    grep "trustPartner:" trusts/trusts.ldif | awk '{print $2}' | while read -r partner; do
        echo "Trust: $partner" >> trusts/selective_auth_status.txt
        
        # Get trust attributes
        local attrs=$(grep -A5 "trustPartner: $partner" trusts/trusts.ldif | grep "trustAttributes:" | awk '{print $2}')
        attrs="${attrs//[^0-9]/}"
        [ -z "$attrs" ] && attrs=0
        
        # Check CROSS_ORGANIZATION bit (16) - indicates selective authentication
        if [ $((attrs & 16)) -ne 0 ]; then
            echo "  Status: ✓ Selective Authentication ENABLED" >> trusts/selective_auth_status.txt
            echo "  Security: GOOD (least privilege)" >> trusts/selective_auth_status.txt
        else
            echo "  Status: ⚠ Forest-wide authentication" >> trusts/selective_auth_status.txt
            echo "  Security: Consider enabling selective authentication" >> trusts/selective_auth_status.txt
            
            add_finding "LOW" "Selective Authentication" \
                "Trust with $partner uses forest-wide authentication (not selective)" \
                "Consider enabling selective authentication for least privilege"
        fi
        
        echo "" >> trusts/selective_auth_status.txt
    done
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 7. Analyze Trust Direction (Attack Paths)
################################################################################
analyze_trust_direction() {
    log_action "Analyzing trust direction for attack paths..."
    ((TOTAL_CHECKS++))
    
    if [ ! -f "trusts/trusts.ldif" ]; then
        ((FAILED_CHECKS++))
        return
    fi
    
    echo "=== TRUST DIRECTION & ATTACK PATH ANALYSIS ===" > trusts/trust_attack_paths.txt
    echo "" >> trusts/trust_attack_paths.txt
    
    local current_partner=""
    local current_direction=""
    
    while IFS= read -r line; do
        if [[ "$line" == trustPartner:* ]]; then
            current_partner=$(echo "$line" | cut -d' ' -f2-)
        elif [[ "$line" == trustDirection:* ]]; then
            current_direction=$(echo "$line" | awk '{print $2}')
            
            echo "Trust: $DOMAIN ←→ $current_partner" >> trusts/trust_attack_paths.txt
            
            case "$current_direction" in
                1)
                    echo "Direction: INBOUND ($current_partner trusts $DOMAIN)" >> trusts/trust_attack_paths.txt
                    echo "Attack Path: You CANNOT directly access $current_partner" >> trusts/trust_attack_paths.txt
                    echo "            BUT: Users from $current_partner can access $DOMAIN" >> trusts/trust_attack_paths.txt
                    echo "Risk: Medium - Incoming principals need monitoring" >> trusts/trust_attack_paths.txt
                    ;;
                2)
                    echo "Direction: OUTBOUND ($DOMAIN trusts $current_partner)" >> trusts/trust_attack_paths.txt
                    echo "Attack Path: You CAN access resources in $current_partner" >> trusts/trust_attack_paths.txt
                    echo "            Users from $DOMAIN can authenticate to $current_partner" >> trusts/trust_attack_paths.txt
                    echo "Risk: High - Potential privilege escalation path" >> trusts/trust_attack_paths.txt
                    
                    add_finding "MEDIUM" "Outbound Trust" \
                        "Outbound trust to $current_partner - potential lateral movement path" \
                        "Enumerate $current_partner for vulnerabilities"
                    ;;
                3)
                    echo "Direction: BIDIRECTIONAL (mutual trust)" >> trusts/trust_attack_paths.txt
                    echo "Attack Path: Full bidirectional access between domains" >> trusts/trust_attack_paths.txt
                    echo "            Compromise in either domain affects the other" >> trusts/trust_attack_paths.txt
                    echo "Risk: High - Bidirectional attack surface" >> trusts/trust_attack_paths.txt
                    
                    add_finding "MEDIUM" "Bidirectional Trust" \
                        "Bidirectional trust with $current_partner - mutual attack surface" \
                        "Verify trust necessity | Consider one-way trust"
                    ;;
                *)
                    echo "Direction: Unknown or Disabled" >> trusts/trust_attack_paths.txt
                    ;;
            esac
            
            echo "" >> trusts/trust_attack_paths.txt
        fi
    done < trusts/trusts.ldif
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 8. Enumerate Foreign Security Principals
################################################################################
enumerate_foreign_principals() {
    log_action "Enumerating foreign security principals..."
    ((TOTAL_CHECKS++))
    
    run_ldap "(objectClass=foreignSecurityPrincipal)" "trusts/foreign_principals.ldif" \
        "Finding foreign security principals" "distinguishedName objectSid"
    
    local fsp_count=$(grep -c "^dn:" trusts/foreign_principals.ldif 2>/dev/null || echo 0)
    fsp_count="${fsp_count//[^0-9]/}"
    [ -z "$fsp_count" ] && fsp_count=0
    
    if [ $fsp_count -gt 0 ]; then
        log_success "Found $fsp_count foreign security principals"
        
        # Check if any have high privileges
        run_ldap "(&(objectClass=group)(member=CN=*,CN=ForeignSecurityPrincipals,*))" \
            "trusts/foreign_group_members.ldif" "Finding groups with foreign members" "distinguishedName member"
        
        local foreign_in_groups=$(grep -c "^dn:" trusts/foreign_group_members.ldif 2>/dev/null || echo 0)
        
        if [ $foreign_in_groups -gt 0 ]; then
            add_finding "MEDIUM" "Foreign Security Principals" \
                "$foreign_in_groups groups contain foreign security principals" \
                "Review trusts/foreign_group_members.ldif | Verify trust necessity"
        fi
        
        ((SUCCESSFUL_CHECKS++))
    else
        log_info "No foreign security principals found"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# BONUS: Trust Exploitation Commands
################################################################################
generate_trust_exploitation_guide() {
    if [ ! -f "trusts/trusts.ldif" ]; then
        return
    fi
    
    cat > trusts/trust_exploitation_guide.txt << 'EOFGUIDE'
╔══════════════════════════════════════════════════════════════════════╗
║  TRUST EXPLOITATION GUIDE                                            ║
╚══════════════════════════════════════════════════════════════════════╝

OUTBOUND TRUST EXPLOITATION:
────────────────────────────────────────────────────────────────────────
If you have an outbound trust (your domain trusts another):

1. Enumerate the trusted domain:
   ldapsearch -H ldap://TRUSTED_DC -D "USER@CURRENT_DOMAIN" -w PASSWORD \
     -b "DC=trusted,DC=domain" "(objectClass=user)"

2. Access resources in trusted domain:
   smbclient //TRUSTED_SERVER/Share -U "CURRENT_DOMAIN\username%password"

3. Check for privilege escalation in trusted domain:
   Import their BloodHound data and look for paths from your domain

BIDIRECTIONAL TRUST EXPLOITATION:
────────────────────────────────────────────────────────────────────────
1. Compromise in either domain = potential compromise of both
2. Look for foreign security principals in privileged groups
3. Golden Ticket attacks can cross trust boundaries

SID FILTERING DISABLED (TREAT_AS_EXTERNAL):
────────────────────────────────────────────────────────────────────────
1. Create a golden ticket with SID history:
   impacket-ticketer -nthash KRBTGT_HASH -domain DOMAIN -domain-sid DOMAIN_SID \
     -extra-sid TRUSTED_DOMAIN_ADMIN_SID USER

2. Use ticket to access trusted domain as Domain Admin

SID INJECTION ATTACK CHAIN:
────────────────────────────────────────────────────────────────────────
1. Compromise current domain
2. Extract KRBTGT hash
3. Identify trusted domain's Domain Admin SID
4. Create golden ticket with extra-sid
5. Access trusted domain with DA privileges

╔══════════════════════════════════════════════════════════════════════╗
║  DEFENSE RECOMMENDATIONS                                             ║
╚══════════════════════════════════════════════════════════════════════╝

1. Enable SID filtering on all external trusts:
   netdom trust DOMAIN /domain:TRUSTED_DOMAIN /quarantine:yes

2. Use selective authentication:
   netdom trust DOMAIN /domain:TRUSTED_DOMAIN /selauth:yes

3. Limit trust to one-way if bidirectional not required

4. Monitor foreign security principals in privileged groups

5. Regular audit of trust relationships

6. Enable AES encryption for trust authentication
EOFGUIDE
}
