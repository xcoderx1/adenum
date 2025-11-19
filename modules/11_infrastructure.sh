#!/bin/bash
run_infrastructure_enum() {
    echo -e "${YELLOW}PHASE 11: Infrastructure Discovery${NC}"
    run_ldap "(&(objectClass=computer)(servicePrincipalName=*MSSQL*))" "infrastructure/mssql.ldif" "Finding MSSQL servers"
    run_ldap "(&(objectClass=computer)(servicePrincipalName=*exchange*))" "infrastructure/exchange.ldif" "Finding Exchange servers"
    echo ""
}