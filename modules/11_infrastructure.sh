#!/bin/bash
run_infrastructure_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 11: Infrastructure Discovery (SPN-based service mapping)      ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    mkdir -p infrastructure

    local cnt hosts

    # MSSQL database servers
    run_ldap "(&(objectClass=computer)(servicePrincipalName=*MSSQL*))" \
        "infrastructure/mssql.ldif" "Finding MSSQL servers" \
        "sAMAccountName dNSHostName servicePrincipalName"
    cnt=$(ldif_count_dn infrastructure/mssql.ldif)
    if [ "$cnt" -gt 0 ]; then
        hosts=$(ldif_values dNSHostName infrastructure/mssql.ldif | grep -v '^$' | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')
        log_success "Found $cnt MSSQL server(s)"
        add_finding "INFO" "Infrastructure" "$cnt MSSQL server(s): $hosts" "Review infrastructure/mssql.ldif"
    fi

    # Exchange mail servers
    run_ldap "(servicePrincipalName=*exchange*)" \
        "infrastructure/exchange.ldif" "Finding Exchange servers" \
        "sAMAccountName dNSHostName servicePrincipalName"
    cnt=$(ldif_count_dn infrastructure/exchange.ldif)
    if [ "$cnt" -gt 0 ]; then
        hosts=$(ldif_values dNSHostName infrastructure/exchange.ldif | grep -v '^$' | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')
        log_success "Found $cnt Exchange server(s)"
        add_finding "INFO" "Infrastructure" "$cnt Exchange server(s): $hosts" "Review infrastructure/exchange.ldif"
    fi

    # SCCM / Configuration Manager (remote control service SPN)
    run_ldap "(servicePrincipalName=*CmRcService*)" \
        "infrastructure/sccm.ldif" "Finding SCCM servers" \
        "sAMAccountName dNSHostName servicePrincipalName"
    cnt=$(ldif_count_dn infrastructure/sccm.ldif)
    if [ "$cnt" -gt 0 ]; then
        hosts=$(ldif_values dNSHostName infrastructure/sccm.ldif | grep -v '^$' | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')
        log_success "Found $cnt SCCM server(s)"
        add_finding "INFO" "Infrastructure" "$cnt SCCM server(s): $hosts" "Review infrastructure/sccm.ldif"
    fi

    # ADFS federation servers
    run_ldap "(servicePrincipalName=*adfs*)" \
        "infrastructure/adfs.ldif" "Finding ADFS servers" \
        "sAMAccountName dNSHostName servicePrincipalName"
    cnt=$(ldif_count_dn infrastructure/adfs.ldif)
    if [ "$cnt" -gt 0 ]; then
        hosts=$(ldif_values dNSHostName infrastructure/adfs.ldif | grep -v '^$' | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')
        log_success "Found $cnt ADFS server(s)"
        add_finding "INFO" "Infrastructure" "$cnt ADFS server(s): $hosts" "Review infrastructure/adfs.ldif"
    fi

    # HTTP SPNs (WSUS / web / WinRM service hosts) - higher volume, count + INFO
    run_ldap "(servicePrincipalName=*HTTP*)" \
        "infrastructure/http_spns.ldif" "Finding HTTP/web service SPNs" \
        "sAMAccountName dNSHostName servicePrincipalName"
    cnt=$(ldif_count_dn infrastructure/http_spns.ldif)
    if [ "$cnt" -gt 0 ]; then
        hosts=$(ldif_values dNSHostName infrastructure/http_spns.ldif | grep -v '^$' | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')
        log_success "Found $cnt host(s) with HTTP SPNs"
        add_finding "INFO" "Infrastructure" "$cnt host(s) with HTTP SPN(s): $hosts" "Review infrastructure/http_spns.ldif"
    fi

    echo ""
}