#!/bin/bash
run_gpo_enum() {
    echo -e "${YELLOW}PHASE 5: GPO Enumeration${NC}"
    run_ldap "(objectClass=groupPolicyContainer)" "gpo/all_gpos.ldif" "Enumerating GPOs"
    run_ldap "(gPLink=*)" "gpo/gpo_links.ldif" "Finding GPO links"
    # Add: SYSVOL credential hunting with smbclient
    echo ""
}