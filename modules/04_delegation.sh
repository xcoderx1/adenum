#!/bin/bash
################################################################################
# MODULE: Delegation Enumeration
# Coverage: Unconstrained, Constrained, RBCD
################################################################################

run_delegation_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 4: Delegation Configurations                                   ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Unconstrained delegation - COMPUTERS
    run_ldap "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        "delegation/01_unconstrained_computers.ldif" "Finding computers with unconstrained delegation" "sAMAccountName dNSHostName"
    
    local uncon_comp_count=$(grep -c "^dn:" "delegation/01_unconstrained_computers.ldif" 2>/dev/null || echo 0)
    if [ $uncon_comp_count -gt 0 ]; then
        # Check if any are NOT domain controllers
        local non_dc=$(grep -v -i "CN=Domain Controllers" "delegation/01_unconstrained_computers.ldif" | grep -c "^dn:" || echo 0)
        if [ $non_dc -gt 0 ]; then
            add_finding "CRITICAL" "Unconstrained Delegation" "$non_dc non-DC computers with unconstrained delegation" \
                "Coerce DC auth → Capture TGT → DCSync | Tools: PetitPotam, PrinterBug, Rubeus"
        fi
    fi
    
    # Unconstrained delegation - USERS
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        "delegation/01_unconstrained_users.ldif" "Finding users with unconstrained delegation" "sAMAccountName"
    
    local uncon_user_count=$(grep -c "^dn:" "delegation/01_unconstrained_users.ldif" 2>/dev/null || echo 0)
    if [ $uncon_user_count -gt 0 ]; then
        add_finding "CRITICAL" "Unconstrained Delegation" "$uncon_user_count user accounts with unconstrained delegation!" \
            "Can impersonate ANY user in domain! Remove this setting immediately."
    fi
    
    # Constrained delegation
    run_ldap "(msDS-AllowedToDelegateTo=*)" \
        "delegation/02_constrained.ldif" "Finding constrained delegation" "sAMAccountName msDS-AllowedToDelegateTo"
    
    local const_count=$(grep -c "^dn:" "delegation/02_constrained.ldif" 2>/dev/null || echo 0)
    if [ $const_count -gt 0 ]; then
        add_finding "HIGH" "Constrained Delegation" "$const_count accounts with constrained delegation" \
            "Review allowed services - can impersonate users to those services"
    fi
    
    # Resource-Based Constrained Delegation (RBCD)
    run_ldap "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "delegation/03_rbcd.ldif" "Finding RBCD configurations" "sAMAccountName"
    
    local rbcd_count=$(grep -c "^dn:" "delegation/03_rbcd.ldif" 2>/dev/null || echo 0)
    if [ $rbcd_count -gt 0 ]; then
        add_finding "MEDIUM" "RBCD" "$rbcd_count objects with RBCD configured" \
            "Review msDS-AllowedToActOnBehalfOfOtherIdentity attribute"
    fi
    
    # Accounts trusted for delegation
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        "delegation/04_trusted_for_delegation.ldif" "Finding accounts trusted for delegation"
    
    # Accounts trusted to authenticate for delegation (protocol transition)
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" \
        "delegation/05_trusted_to_auth.ldif" "Finding accounts trusted to authenticate for delegation"
    
    local auth_del_count=$(grep -c "^dn:" "delegation/05_trusted_to_auth.ldif" 2>/dev/null || echo 0)
    if [ $auth_del_count -gt 0 ]; then
        add_finding "HIGH" "Protocol Transition" "$auth_del_count accounts can authenticate for delegation (protocol transition)" \
            "Can obtain service tickets without user's password"
    fi
    
    echo ""
}
