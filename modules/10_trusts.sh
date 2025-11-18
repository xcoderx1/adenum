#!/bin/bash
run_trust_enum() {
    echo -e "${YELLOW}PHASE 10: Trust Relationships${NC}"
    run_ldap "(objectClass=trustedDomain)" "trusts/trusts.ldif" "Enumerating domain trusts"
    echo ""
}